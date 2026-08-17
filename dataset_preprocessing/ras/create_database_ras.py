"""RAS dataset preprocessing - create PostgreSQL database from RAS capture CSVs.

Parses RAS capture telemetry (one CSV per capture, 23 columns) and populates the
PostgreSQL database with nodes (subjects, files, netflows) and events (edges) for
graph construction.

RAS ships one dataset per scenario. The verb vocabulary is not new: the relation map
comes from get_rel2id(cfg), so a Linux scenario falls through to rel2id_darpa_tc and a
Windows scenario resolves to rel2id_graph_processor_carbon_black_edr by virtue of its
membership in graph_processor_carbon_black_edr_datasets.

Node identity comes from the telemetry alone:

    subject   (actor_pid, actor_pid_ts)   capture-scoped; empty pid_ts = predates the capture
    file      object_path                 object_type file or directory
    registry  object_path                 stored in the file table, three node types exist
    netflow   (remote_ip, remote_port)    object_type ipv4 or ipv6

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
    "object_type,object_path,fd_num,local_ip,local_port,remote_ip,remote_port,uid,"
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
    return [
        {"name": c, "date": d, "telemetry": os.path.join(raw_dir, f)}
        for c, d, f in CAPTURES[name]
    ]


def subject_uuid(capture, pid, pts):
    return "subject:%s:%s:%s" % (capture, pid, pid_ts(pts))


def object_uuid(otype, path, ip, port):
    if otype == "netflow":
        return "netflow:%s:%s" % (ip, port)
    return "%s:%s" % (otype, norm(path))


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


def save_nodes(cfg, captures):
    """First pass: intern every node reachable from a kept event.

    Object identity is global by path, so the same system file in two captures is one
    node, which is what lets a model recognise it after training on a different capture.
    Process identity is capture-scoped, because captures are independent VM restores and
    a pre-existing pid would otherwise collide across them.
    """
    rel2id = get_rel2id(cfg)

    subject_uuid2attr = {}
    file_uuid2attr = {}
    netflow_uuid2attr = {}
    capture_origin = {}

    for i, c in enumerate(captures):
        name, path = c["name"], c["telemetry"]
        for row in tqdm(
            read_capture(path),
            desc=f"Extracting nodes from {i}-th/{len(captures)} capture ({name}).",
        ):
            raw_ts = row[IX["ts_ns"]]
            if not raw_ts:
                continue
            if name not in capture_origin:
                capture_origin[name] = int(raw_ts)

            operation = row[IX["operation"]]
            if operation in exclude_edge_type or operation not in rel2id:
                continue

            pid, pts = row[IX["actor_pid"]], row[IX["actor_pid_ts"]]
            subject_uuid2attr[subject_uuid(name, pid, pts)] = (
                row[IX["actor_exepath"]] or None,
                row[IX["actor_cmdline"]] or None,
            )

            remote_ip = row[IX["remote_ip"]]
            object_path = row[IX["object_path"]]

            if remote_ip:
                remote_port = row[IX["remote_port"]]
                uuid = object_uuid("netflow", None, remote_ip, remote_port)
                netflow_uuid2attr[uuid] = (None, None, remote_ip, remote_port)
            elif object_path:
                otype = OBJECT_TYPE.get(row[IX["object_type"]])
                if otype is None:
                    continue
                uuid = object_uuid(otype, object_path, None, None)
                file_uuid2attr[uuid] = norm(object_path)
            else:
                # No object on the row. Process-creation events name their other endpoint
                # in the parent columns: the row IS the child, the parent is actor_ppid.
                # Interning that parent keeps a spawned process connected to its spawner.
                ppid, ppts = row[IX["actor_ppid"]], row[IX["actor_ppid_ts"]]
                if not ppid or (ppid == pid and pid_ts(ppts) == pid_ts(pts)):
                    continue
                parent = subject_uuid(name, ppid, ppts)
                subject_uuid2attr.setdefault(parent, (None, None))

    index_id = 0
    cur, connect = init_database_connection(cfg)
    # uuid -> (hash_id, index_id). The event table stores the hash as src_node/dst_node and
    # the index as src_index_id/dst_index_id, as create_database_e3.py does.
    uuid2node = {}

    # Save subject_nodes
    datalist = []
    for sub_uuid, sub_attr in tqdm(
        subject_uuid2attr.items(), desc="Processing datalist for subject nodes"
    ):
        hash_id = stringtomd5(sub_uuid)
        datalist.append([sub_uuid, hash_id, sub_attr[0], sub_attr[1], index_id])
        uuid2node[sub_uuid] = (hash_id, index_id)
        index_id += 1

    log("Start saving subject nodes.")
    sql = """insert into subject_node_table
                             values %s
                """
    ex.execute_values(cur, sql, datalist, page_size=10000)
    connect.commit()
    log("Finished saving subject nodes.")
    del subject_uuid2attr
    del datalist

    # Save file_nodes
    datalist = []
    for file_uuid, file_attr in tqdm(file_uuid2attr.items(), desc="Processing file nodes"):
        hash_id = stringtomd5(file_uuid)
        datalist.append([file_uuid, hash_id, file_attr, index_id])
        uuid2node[file_uuid] = (hash_id, index_id)
        index_id += 1

    log("Start saving file nodes.")
    sql = """insert into file_node_table
                             values %s
                """
    ex.execute_values(cur, sql, datalist, page_size=10000)
    connect.commit()
    log("Finished saving file nodes.")
    del file_uuid2attr
    del datalist

    # Save netflow_nodes
    datalist = []
    for net_uuid, net_attr in tqdm(netflow_uuid2attr.items(), desc="Processing net nodes"):
        hash_id = stringtomd5(net_uuid)
        datalist.append(
            [
                net_uuid,
                hash_id,
                net_attr[0],
                net_attr[1],
                net_attr[2],
                net_attr[3],
                index_id,
            ]
        )
        uuid2node[net_uuid] = (hash_id, index_id)
        index_id += 1

    log("Start saving net nodes.")
    sql = """insert into netflow_node_table
                             values %s
                """
    ex.execute_values(cur, sql, datalist, page_size=10000)
    connect.commit()
    log("Finished saving net nodes.")
    del netflow_uuid2attr
    del datalist

    return uuid2node, capture_origin


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


def save_events(cfg, uuid2node, capture_origin, captures, batch=400_000):
    rel2id = get_rel2id(cfg)
    object_is_src = get_object_is_src(cfg)

    cur, connect = init_database_connection(cfg)
    unknown = Counter()

    for i, c in enumerate(captures):
        name, path, date = c["name"], c["telemetry"], c["date"]
        base = datetime_to_ns_time_US("%s 00:00:00" % date)
        origin = capture_origin[name]
        datalist = []
        stats = Counter()

        for row in tqdm(
            read_capture(path),
            desc=f"Extracting events from {i}-th/{len(captures)} capture ({name}).",
        ):
            raw_ts = row[IX["ts_ns"]]
            if not raw_ts:
                continue
            timestamp = base + (int(raw_ts) - origin)

            operation = row[IX["operation"]]
            if operation in exclude_edge_type:
                continue
            if operation not in rel2id:
                unknown[operation] += 1
                continue

            pid, pts = row[IX["actor_pid"]], row[IX["actor_pid_ts"]]
            src_uuid = subject_uuid(name, pid, pts)
            event_uuid = "%s:%s" % (name, row[IX["event_num"]])

            remote_ip = row[IX["remote_ip"]]
            object_path = row[IX["object_path"]]

            if remote_ip:
                dst_uuid = object_uuid("netflow", None, remote_ip, row[IX["remote_port"]])
            elif object_path:
                otype = OBJECT_TYPE.get(row[IX["object_type"]])
                if otype is None:
                    continue
                dst_uuid = object_uuid(otype, object_path, None, None)
            else:
                ppid, ppts = row[IX["actor_ppid"]], row[IX["actor_ppid_ts"]]
                if not ppid or (ppid == pid and pid_ts(ppts) == pid_ts(pts)):
                    continue
                parent_uuid = subject_uuid(name, ppid, ppts)
                if (parent_uuid not in uuid2node) or (src_uuid not in uuid2node):
                    continue
                parent_hash, parent_index = uuid2node[parent_uuid]
                src_hash, src_index = uuid2node[src_uuid]
                # The parent spawns the child, so the edge runs parent -> child.
                datalist.append(
                    [
                        parent_hash,
                        parent_index,
                        operation,
                        src_hash,
                        src_index,
                        event_uuid,
                        timestamp,
                    ]
                )
                stats["process_edges"] += 1
                if len(datalist) >= batch:
                    copy_events(cur, datalist)
                    datalist = []
                continue

            if (src_uuid not in uuid2node) or (dst_uuid not in uuid2node):
                continue
            src_hash, src_index_id = uuid2node[src_uuid]
            dst_hash, dst_index_id = uuid2node[dst_uuid]

            if operation in object_is_src:
                datalist.append(
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
                datalist.append(
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
            if len(datalist) >= batch:
                copy_events(cur, datalist)
                datalist = []

        log(f"Start saving events for {i}-th/{len(captures)} capture ({name}).")
        copy_events(cur, datalist)
        connect.commit()
        log(
            f"Finish saving events for {i}-th/{len(captures)} capture ({name}): "
            f"kept={stats['kept']} process_edges={stats['process_edges']}."
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

    uuid2node, capture_origin = save_nodes(cfg, captures)
    log("Finished saving nodes.")

    save_events(cfg, uuid2node, capture_origin, captures)
    log("Finished saving events.")
