#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: run-ras-job.sh SYSTEM DATASET DUMP_FILE [PIDSMaker options]

Run one RAS scenario with a PostgreSQL server owned by the current scheduler job.

Environment:
  POSTGRES_IMAGE     Persistent postgres.sif path.
  POSTGRES_DATA_DIR  PostgreSQL data directory for this scenario and job.
    POSTGRES_RUN_DIR   Job-local PostgreSQL Unix socket directory.
  ARTIFACT_DIR       PIDSMaker output directory.
  JOB_TAG            Unique job name. Defaults to PBS_JOBID or SLURM_JOB_ID.
EOF
}

if (( $# < 3 )); then
    usage >&2
    exit 2
fi

SYSTEM=$1
DATASET=${2^^}
DUMP_FILE=$3
shift 3

case "$DATASET" in
    RAS_GARONNE) DATABASE=ras_garonne ;;
    RAS_SEVERN) DATABASE=ras_severn ;;
    *) echo "Unsupported RAS dataset: $DATASET" >&2; exit 2 ;;
esac

[[ -f "$DUMP_FILE" ]] || { echo "Dump file not found: $DUMP_FILE" >&2; exit 1; }
DUMP_FILE=$(readlink -f "$DUMP_FILE")

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
JOB_TAG=${JOB_TAG:-${PBS_JOBID:-${SLURM_JOB_ID:-local}}}
JOB_TAG=${JOB_TAG//[^A-Za-z0-9_.-]/_}
POSTGRES_INSTANCE=${POSTGRES_INSTANCE:-postgres_${JOB_TAG}_${DATABASE}}
JOB_ROOT=${JOB_ROOT:-${TMPDIR:-/tmp}/pidsmaker-${JOB_TAG}-${DATABASE}}
POSTGRES_DATA_DIR=${POSTGRES_DATA_DIR:-${JOB_ROOT}/postgres-data}
POSTGRES_RUN_DIR=${POSTGRES_RUN_DIR:-${JOB_ROOT}/postgres-run}
POSTGRES_LOG_DIR=${POSTGRES_LOG_DIR:-${JOB_ROOT}/postgres-log}
ARTIFACT_DIR=${ARTIFACT_DIR:-${REPO_ROOT}/artifacts/${JOB_TAG}-${DATABASE}}
POSTGRES_IMAGE=${POSTGRES_IMAGE:-${SCRIPT_DIR}/postgres.sif}

mkdir -p "$POSTGRES_DATA_DIR" "$POSTGRES_RUN_DIR" "$POSTGRES_LOG_DIR" "$ARTIFACT_DIR"

export JOB_TAG POSTGRES_INSTANCE POSTGRES_IMAGE
export RUNTIME_ROOT="$JOB_ROOT"
export POSTGRES_DATA_DIR POSTGRES_RUN_DIR POSTGRES_LOG_DIR
export POSTGRES_PID_FILE="${JOB_ROOT}/instance.pid"

cleanup() {
    "$SCRIPT_DIR/postgres-stop.sh" || true
}
trap cleanup EXIT INT TERM

(
    cd "$SCRIPT_DIR"
    INPUT_DIR=$(dirname "$DUMP_FILE") ./postgres-start.sh
)

if command -v apptainer >/dev/null 2>&1; then
    CONTAINER_CMD=apptainer
elif command -v singularity >/dev/null 2>&1; then
    CONTAINER_CMD=singularity
else
    echo "Neither apptainer nor singularity is available." >&2
    exit 1
fi

"$CONTAINER_CMD" exec "instance://${POSTGRES_INSTANCE}" \
    /scripts/load_dumps.sh \
    --file "/data/$(basename "$DUMP_FILE")" \
    --database "$DATABASE" \
    --host /var/run/postgresql \
    --user postgres

"$CONTAINER_CMD" exec "instance://${POSTGRES_INSTANCE}" \
    psql -h /var/run/postgresql -U postgres -d "$DATABASE" \
    -v ON_ERROR_STOP=1 -Atc "SELECT COUNT(*) FROM event_table;"

cd "$REPO_ROOT"
python pidsmaker/main.py "$SYSTEM" "$DATASET" \
    --database_host "$POSTGRES_RUN_DIR" \
    --database_user postgres \
    --database_password postgres \
    --artifact_dir "$ARTIFACT_DIR" \
    "$@"