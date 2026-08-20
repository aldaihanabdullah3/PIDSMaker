"""RAS dataset preprocessing - create PostgreSQL database from RAS capture CSVs.

Parses RAS capture telemetry (one CSV per capture, 24 columns) and populates the
PostgreSQL database with nodes (subjects, files, netflows) and events (edges) for
graph construction.

Each telemetry file is read once. For attack captures, the loader first reads the
matching propagation ``*_gt.csv`` file and keeps only MALICIOUS rows. During the
telemetry pass, it records exact database UUIDs and assigned index IDs for infected
subjects, files, registry objects, and process-scoped network sessions. It writes
``<attack>.csv`` with all matched nodes and ``<attack>_subjects.csv`` with subjects
only. Benign captures do not load or write ground truth.

RAS ships one dataset per scenario. The verb vocabulary is not new: the relation map
comes from get_rel2id(cfg), so a Linux scenario falls through to rel2id_darpa_tc and a
Windows scenario resolves to rel2id_graph_processor_carbon_black_edr by virtue of its
membership in graph_processor_carbon_black_edr_datasets.

Node identity comes from the telemetry alone:

    subject   (actor_pid, actor_pid_ts)
    file      (subject UUID, normalized object_path)
    registry  (subject UUID, normalized object_path), stored in the file table
    netflow   (subject UUID, protocol, local endpoint, remote endpoint)

This process-scoped object contract follows evidence from PIDSMaker's existing source
databases. One path maps to many producer UUIDs in OpTC, THEIA E3/E5, and AtlasV2.
Their object lifetimes differ: sampled THEIA E3 and most AtlasV2 objects are short-lived,
while THEIA E5 also has UUIDs shared by processes and days. RAS has no producer object
UUID, so process scoping is a controlled approximation that prevents unrelated process
and capture activity from collapsing onto one path or endpoint node. Node features still
store the path or endpoints, so separate UUIDs retain common semantic attributes.

Every capture is an independent VM restored from the same image, so wall-clock time
carries no information and several captures share calendar dates. Each is rebased onto a
synthetic date of its own, computed with datetime_to_ns_time_US so its US/Eastern
localisation cancels out.

The capture list is the CAPTURES table below; the directory holding them is given by --raw_dir.
"""

import argparse
import csv
import hashlib
import io

import os
import sys
from collections import Counter

from psycopg2 import extras as ex
from tqdm import tqdm

from pidsmaker.config import get_runtime_required_args, get_yml_cfg
from pidsmaker.utils.dataset_utils import (
    edge_reversed,
    exclude_edge_type,
    get_rel2id,
    graph_processor_carbon_black_edr_datasets,
)
from pidsmaker.utils.utils import (
    datetime_to_ns_time_US,
    init_database_connection,
    log,
)


def stringtomd5(originstr):
    # Defined locally and hashing the node uuid, as create_database_e3.py does. Despite the
    # name it is sha256 there too. Note that create_database_optc.py instead hashes the node
    # attributes, which collapses distinct nodes that happen to share attributes onto one
    # hash_id; since hash_id is what the event table stores as src_node/dst_node, that would
    # misattribute edges.
    originstr = originstr.encode("utf-8")
    signaturemd5 = hashlib.sha256()
    signaturemd5.update(originstr)
    return signaturemd5.hexdigest()

csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

COLUMNS = (
    "event_num,ts_ns,syscall,operation,res,actor_pid,actor_pid_ts,actor_tid,"
    "actor_ppid,actor_ppid_ts,actor_name,actor_exepath,actor_cmdline,parent_exepath,"
    "object_type,object_path,fd_num,local_ip,local_port,remote_ip,remote_port,protocol,uid,"
    "extra_info"
).split(",")
IX = {c: i for i, c in enumerate(COLUMNS)}

# object_type -> PIDSMaker node type. The framework has three; registry joins file,
# following the ATLASv2 and Carbanak precedent.
OBJECT_TYPE = {
    "file": "file",
    "directory": "file",
    "registry": "registry",
    "ipv4": "netflow",
    "ipv6": "netflow",
}

# Operations whose object is the source and the process the destination: data flowing in.
# The DARPA-TC vocabulary takes the framework's own edge_reversed list; the Carbon Black
# verbs are absent from it and are named here.
CARBON_BLACK_OBJECT_IS_SRC = {
    "FILE_READ",
    "MODULE_LOADED",
    "REGISTRY_KEY_LOADED",
    "REGISTRY_VALUE_READ",
    "NETFLOW_PACKET_RECEIVED",
}

# A pre-existing process reports "" for its own start time but "0" when named as
# someone's parent. Both mean the same thing and must fold to one identity.
PREEXISTING = ("", "0")

# (capture name, synthetic date, telemetry filename relative to cfg.dataset.raw_dir).
#
# Captures are independent VM restores from the same clean snapshot, so wall-clock time
# carries no information and several captures share a calendar date in the raw data. Each is
# rebased onto a synthetic date of its own, which is what lets a single tier be evaluated in
# isolation by putting one date in test_dates. Dates are spaced two apart so a ~24.3h benign
# capture spills its overflow onto a date that is in no split.
#
# These dates must match train_dates / val_dates / test_dates in DATASET_DEFAULT_CONFIG.
CAPTURES = {
    "RAS_GARONNE": [
        ("benign_sysdig_1", "2026-01-01", "benign_sysdig_1.csv"),
        ("benign_sysdig_2", "2026-01-03", "benign_sysdig_2.csv"),
        ("benign_sysdig_3", "2026-01-05", "benign_sysdig_3.csv"),
        ("benign_sysdig_4", "2026-01-07", "benign_sysdig_4.csv"),
        ("benign_sysdig_5", "2026-01-09", "benign_sysdig_5.csv"),
        ("benign_sysdig_6", "2026-01-11", "benign_sysdig_6.csv"),
        ("benign_sysdig_7", "2026-01-13", "benign_sysdig_7.csv"),
        ("benign_sysdig_8", "2026-01-15", "benign_sysdig_8.csv"),
        ("loud_sysdig", "2026-01-17", "loud_sysdig.csv"),
        ("medium_sysdig", "2026-01-19", "medium_sysdig.csv"),
        ("hard_sysdig", "2026-01-21", "hard_sysdig.csv"),
        ("evasive_sysdig", "2026-01-23", "evasive_sysdig.csv"),
    ],
    "RAS_SEVERN": [
        ("benign_etw_1", "2026-01-01", "benign_etw_1.csv"),
        ("benign_etw_2", "2026-01-03", "benign_etw_2.csv"),
        ("benign_etw_3", "2026-01-05", "benign_etw_3.csv"),
        ("benign_etw_4", "2026-01-07", "benign_etw_4.csv"),
        ("benign_etw_5", "2026-01-09", "benign_etw_5.csv"),
        ("benign_etw_6", "2026-01-11", "benign_etw_6.csv"),
        ("benign_etw_7", "2026-01-13", "benign_etw_7.csv"),
        ("benign_etw_8", "2026-01-15", "benign_etw_8.csv"),
        ("loud_etw", "2026-01-17", "loud_etw.csv"),
        ("medium_etw", "2026-01-19", "medium_etw.csv"),
        ("hard_etw", "2026-01-21", "hard_etw.csv"),
        ("evasive_etw", "2026-01-23", "evasive_etw.csv"),
    ],
}


def norm(p):
    """Case-fold and unify separators, so the OS spelling and a tool's forward-slash
    spelling of the same path land on one node."""
    return (p or "").lower().replace("\\", "/")


def pid_ts(v):
    return "" if v in PREEXISTING else v


def get_object_is_src(cfg):
    """Mirrors the dispatch in get_rel2id: which operations put the object on the left."""
    if cfg.dataset.name.lower() in graph_processor_carbon_black_edr_datasets:
        return CARBON_BLACK_OBJECT_IS_SRC
    rel2id = get_rel2id(cfg)
    return {v for v in edge_reversed if v in rel2id}


def get_captures(cfg, raw_dir):
    """Resolve the capture table for this dataset against the given raw directory."""
    name = cfg.dataset.name.upper()
    if name not in CAPTURES:
        raise SystemExit("no capture table for dataset %r" % name)
    captures = []
    for capture_name, date, filename in CAPTURES[name]:
        attack = capture_name.split("_", 1)[0]
        captures.append(
            {
                "name": capture_name,
                "date": date,
                "telemetry": os.path.join(raw_dir, filename),
                "ground_truth": (
                    os.path.join(raw_dir, "%s_gt.csv" % attack)
                    if attack in {"loud", "medium", "hard", "evasive"}
                    else None
                ),
                "attack": attack if attack in {"loud", "medium", "hard", "evasive"} else None,
            }
        )
    return captures


def subject_uuid(pid, pts):
    return "subject:%s:%s" % (pid, pid_ts(pts))


def object_uuid(otype, process_uuid, path=None, protocol=None, local_ip=None,
                local_port=None, remote_ip=None, remote_port=None):
    if otype == "netflow":
        return "netflow:%s:%s:%s:%s:%s:%s" % (
            process_uuid.removeprefix("subject:"),
            (protocol or "").lower(),
            local_ip or "",
            local_port or "",
            remote_ip or "",
            remote_port or "",
        )
    return "%s:%s:%s" % (otype, process_uuid.removeprefix("subject:"), norm(path))


def read_capture(csv_path):
    """Yield well-formed rows of a capture CSV, rejecting a file whose header has drifted."""
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        r = csv.reader(f)
        hdr = next(r)
        if hdr != COLUMNS:
            raise SystemExit(
                "%s: unexpected header.\n  expected %d columns: %s\n  found    %d columns: %s"
                % (csv_path, len(COLUMNS), ",".join(COLUMNS), len(hdr), ",".join(hdr))
            )
        for row in r:
            if len(row) == len(COLUMNS):
                yield row


def read_ground_truth(path):
    """Index malicious propagation labels for one-pass telemetry matching."""
    labels = {"subjects": {}, "objects": set(), "netflows": {}, "source_keys": set()}
    with open(path, newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        required = {
            "node_key", "node_name", "node_type", "label", "infected_ts_ns",
            "actor_pid", "actor_pid_ts", "object_path", "local_ip", "local_port",
            "remote_ip", "remote_port", "protocol",
        }
        missing = required.difference(reader.fieldnames or ())
        if missing:
            raise SystemExit(
                "%s: missing ground-truth columns: %s"
                % (path, ", ".join(sorted(missing)))
            )
        for row in reader:
            if row["label"].upper() != "MALICIOUS":
                continue
            labels["source_keys"].add(row["node_key"])
            if row["node_type"] == "proc":
                uuid = subject_uuid(row["actor_pid"], row["actor_pid_ts"])
                labels["subjects"][uuid] = {"subject": row["node_name"]}
            elif row["node_type"] in {"file", "registry"}:
                labels["objects"].add((row["infected_ts_ns"], norm(row["object_path"])))
            elif row["node_type"] == "net":
                key = (
                    row["protocol"].lower(),
                    row["local_ip"].lower(),
                    row["remote_ip"].lower(),
                    row["remote_port"],
                )
                labels["netflows"].setdefault(key, set()).update(
                    port for port in row["local_port"].split(";") if port
                )
    return labels


def ground_truth_match(labels, row, node_uuid, node_type):
    if labels is None:
        return None
    if node_type == "subject":
        return labels["subjects"].get(node_uuid)
    if node_type == "file":
        key = (row[IX["ts_ns"]], norm(row[IX["object_path"]]))
        return {"file": row[IX["object_path"]]} if key in labels["objects"] else None
    key = (
        row[IX["protocol"]].lower(),
        row[IX["local_ip"]].lower(),
        row[IX["remote_ip"]].lower(),
        row[IX["remote_port"]],
    )
    ports = labels["netflows"].get(key)
    if ports is None or (ports and row[IX["local_port"]] not in ports):
        return None
    return {
        "netflow": "%s:%s -> %s:%s"
        % (
            row[IX["local_ip"]],
            row[IX["local_port"]],
            row[IX["remote_ip"]],
            row[IX["remote_port"]],
        )
    }


def write_ground_truth(cfg, attack, matched, uuid2node):
    output_dir = os.path.join(cfg._ground_truth_dir, cfg.dataset.database)
    os.makedirs(output_dir, exist_ok=True)
    rows = sorted(
        (uuid, str(message), uuid2node[uuid][1]) for uuid, message in matched.items()
    )
    outputs = {
        "%s.csv" % attack: rows,
        "%s_subjects.csv" % attack: [
            row for row in rows if row[0].startswith("subject:")
        ],
    }
    for filename, selected in outputs.items():
        path = os.path.join(output_dir, filename)
        with open(path, "w", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerows(selected)
        log("Wrote %d ground-truth nodes to %s." % (len(selected), path))


EVENT_COLS = [
    "src_node",
    "src_index_id",
    "operation",
    "dst_node",
    "dst_index_id",
    "event_uuid",
    "timestamp_rec",
]


def copy_events(cur, rows):
    """Bulk insert via COPY rather than execute_values.

    The event table is orders of magnitude larger than the node tables, and COPY is
    substantially faster on it. Swap for ex.execute_values if you need the parity.
    """
    if not rows:
        return
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    for r in rows:
        w.writerow(["" if x is None else x for x in r])
    buf.seek(0)
    cur.copy_expert(
        "COPY event_table (%s) FROM STDIN WITH (FORMAT csv)" % ",".join(EVENT_COLS), buf
    )


def save_all(cfg, captures, node_batch=100_000, event_batch=400_000):
    """Insert nodes and events, and collect ground truth, in one pass per capture."""
    rel2id = get_rel2id(cfg)
    object_is_src = get_object_is_src(cfg)
    cur, connect = init_database_connection(cfg)
    unknown = Counter()
    uuid2node = {}
    next_index = 0
    subject_rows, file_rows, netflow_rows, event_rows = [], [], [], []
    pending_subject_rows = {}
    subject_updates = {}
    subject_attrs = {}

    def intern_subject(uuid, path=None, cmd=None):
        nonlocal next_index
        if uuid not in uuid2node:
            hash_id = stringtomd5(uuid)
            uuid2node[uuid] = (hash_id, next_index)
            node_row = [uuid, hash_id, path, cmd, next_index]
            subject_rows.append(node_row)
            pending_subject_rows[uuid] = node_row
            subject_attrs[uuid] = (bool(path), bool(cmd))
            next_index += 1
        elif path or cmd:
            has_path, has_cmd = subject_attrs[uuid]
            new_path = path if path and not has_path else None
            new_cmd = cmd if cmd and not has_cmd else None
            if not new_path and not new_cmd:
                return uuid2node[uuid]
            node_row = pending_subject_rows.get(uuid)
            if node_row is not None:
                node_row[2] = new_path or node_row[2]
                node_row[3] = new_cmd or node_row[3]
            else:
                old_path, old_cmd = subject_updates.get(uuid, (None, None))
                subject_updates[uuid] = (new_path or old_path, new_cmd or old_cmd)
            subject_attrs[uuid] = (has_path or bool(new_path), has_cmd or bool(new_cmd))
        return uuid2node[uuid]

    def intern_file(uuid, path):
        nonlocal next_index
        if uuid not in uuid2node:
            hash_id = stringtomd5(uuid)
            uuid2node[uuid] = (hash_id, next_index)
            file_rows.append([uuid, hash_id, norm(path), next_index])
            next_index += 1
        return uuid2node[uuid]

    def intern_netflow(uuid, local_ip, local_port, remote_ip, remote_port):
        nonlocal next_index
        if uuid not in uuid2node:
            hash_id = stringtomd5(uuid)
            uuid2node[uuid] = (hash_id, next_index)
            netflow_rows.append(
                [uuid, hash_id, local_ip, local_port, remote_ip, remote_port, next_index]
            )
            next_index += 1
        return uuid2node[uuid]

    def flush_nodes():
        if subject_rows:
            ex.execute_values(cur, "INSERT INTO subject_node_table VALUES %s", subject_rows)
            subject_rows.clear()
            pending_subject_rows.clear()
        if subject_updates:
            ex.execute_values(
                cur,
                """UPDATE subject_node_table AS subject
                   SET path = COALESCE(data.path, subject.path),
                       cmd = COALESCE(data.cmd, subject.cmd)
                   FROM (VALUES %s) AS data(node_uuid, path, cmd)
                   WHERE subject.node_uuid = data.node_uuid""",
                [(uuid, *attrs) for uuid, attrs in subject_updates.items()],
            )
            subject_updates.clear()
        if file_rows:
            ex.execute_values(cur, "INSERT INTO file_node_table VALUES %s", file_rows)
            file_rows.clear()
        if netflow_rows:
            ex.execute_values(cur, "INSERT INTO netflow_node_table VALUES %s", netflow_rows)
            netflow_rows.clear()

    def flush_events():
        flush_nodes()
        copy_events(cur, event_rows)
        event_rows.clear()

    for i, c in enumerate(captures):
        name, path, date = c["name"], c["telemetry"], c["date"]
        labels = read_ground_truth(c["ground_truth"]) if c["ground_truth"] else None
        matched = {}
        object_candidates = {}
        base = datetime_to_ns_time_US("%s 00:00:00" % date)
        origin = None
        stats = Counter()

        for row in tqdm(
            read_capture(path),
            desc=f"Importing {i}-th/{len(captures)} capture ({name}).",
        ):
            raw_ts = row[IX["ts_ns"]]
            if not raw_ts:
                continue
            if origin is None:
                origin = int(raw_ts)
            timestamp = base + (int(raw_ts) - origin)

            object_path = row[IX["object_path"]]
            if labels is not None and object_path:
                infection_key = (raw_ts, norm(object_path))
                object_type = OBJECT_TYPE.get(row[IX["object_type"]])
                if infection_key in labels["objects"] and object_type in {"file", "registry"}:
                    process_uuid = subject_uuid(
                        row[IX["actor_pid"]], row[IX["actor_pid_ts"]]
                    )
                    candidate_uuid = object_uuid(object_type, process_uuid, path=object_path)
                    object_candidates[candidate_uuid] = {"file": object_path}

            operation = row[IX["operation"]]
            if operation in exclude_edge_type:
                continue
            if operation not in rel2id:
                unknown[operation] += 1
                continue

            pid, pts = row[IX["actor_pid"]], row[IX["actor_pid_ts"]]
            src_uuid = subject_uuid(pid, pts)
            src_hash, src_index_id = intern_subject(
                src_uuid,
                row[IX["actor_exepath"]] or None,
                row[IX["actor_cmdline"]] or None,
            )
            message = ground_truth_match(labels, row, src_uuid, "subject")
            if message is not None:
                matched[src_uuid] = message
            event_uuid = "%s:%s" % (name, row[IX["event_num"]])

            remote_ip = row[IX["remote_ip"]]

            if remote_ip:
                dst_uuid = object_uuid(
                    "netflow",
                    src_uuid,
                    protocol=row[IX["protocol"]],
                    local_ip=row[IX["local_ip"]],
                    local_port=row[IX["local_port"]],
                    remote_ip=remote_ip,
                    remote_port=row[IX["remote_port"]],
                )
                dst_hash, dst_index_id = intern_netflow(
                    dst_uuid,
                    row[IX["local_ip"]],
                    row[IX["local_port"]],
                    remote_ip,
                    row[IX["remote_port"]],
                )
                message = ground_truth_match(labels, row, dst_uuid, "netflow")
            elif object_path:
                otype = OBJECT_TYPE.get(row[IX["object_type"]])
                if otype is None:
                    continue
                dst_uuid = object_uuid(otype, src_uuid, path=object_path)
                dst_hash, dst_index_id = intern_file(dst_uuid, object_path)
                message = ground_truth_match(labels, row, dst_uuid, "file")
            else:
                ppid, ppts = row[IX["actor_ppid"]], row[IX["actor_ppid_ts"]]
                if not ppid or (ppid == pid and pid_ts(ppts) == pid_ts(pts)):
                    continue
                parent_uuid = subject_uuid(ppid, ppts)
                parent_hash, parent_index = intern_subject(parent_uuid)
                message = ground_truth_match(labels, row, parent_uuid, "subject")
                if message is not None:
                    matched[parent_uuid] = message
                # The parent spawns the child, so the edge runs parent -> child.
                event_rows.append(
                    [
                        parent_hash,
                        parent_index,
                        operation,
                        src_hash,
                        src_index_id,
                        event_uuid,
                        timestamp,
                    ]
                )
                stats["process_edges"] += 1
                if len(subject_rows) + len(file_rows) + len(netflow_rows) >= node_batch:
                    flush_nodes()
                if len(event_rows) >= event_batch:
                    flush_events()
                continue

            if message is not None:
                matched[dst_uuid] = message

            if operation in object_is_src:
                event_rows.append(
                    [
                        dst_hash,
                        dst_index_id,
                        operation,
                        src_hash,
                        src_index_id,
                        event_uuid,
                        timestamp,
                    ]
                )
            else:
                event_rows.append(
                    [
                        src_hash,
                        src_index_id,
                        operation,
                        dst_hash,
                        dst_index_id,
                        event_uuid,
                        timestamp,
                    ]
                )
            stats["kept"] += 1
            if len(subject_rows) + len(file_rows) + len(netflow_rows) >= node_batch:
                flush_nodes()
            if len(event_rows) >= event_batch:
                flush_events()

        flush_events()
        connect.commit()
        log(
            f"Finished {i}-th/{len(captures)} capture ({name}): "
            f"kept={stats['kept']} process_edges={stats['process_edges']}."
        )
        if labels is not None:
            matched.update(
                (uuid, message)
                for uuid, message in object_candidates.items()
                if uuid in uuid2node
            )
            write_ground_truth(cfg, c["attack"], matched, uuid2node)
            log(
                "Collected %d database ground-truth nodes; the propagation source "
                "contains %d malicious labels."
                % (len(matched), len(labels["source_keys"]))
            )

    cur.execute("CREATE INDEX IF NOT EXISTS event_table_ts_idx ON event_table (timestamp_rec)")
    connect.commit()

    if unknown:
        log("WARNING: verbs seen but absent from the relation map, so absent from every graph:")
        for operation, n in unknown.most_common():
            log("   %-28s %d" % (operation, n))


if __name__ == "__main__":
    # get_runtime_required_args uses parse_known_args, so --raw_dir passes through untouched
    # and is parsed here. This keeps the directory out of DATASET_DEFAULT_CONFIG, where every
    # other dataset leaves raw_dir empty, and off any hardcoded path in this file.
    args, unknown_args = get_runtime_required_args(return_unknown_args=True)
    cfg = get_yml_cfg(args)

    ap = argparse.ArgumentParser()
    ap.add_argument("--raw_dir", required=True, help="Directory holding this dataset's capture CSVs")
    extra, _ = ap.parse_known_args(unknown_args)

    captures = get_captures(cfg, extra.raw_dir)

    save_all(cfg, captures)
    log("Finished saving nodes, events, and ground truth.")
