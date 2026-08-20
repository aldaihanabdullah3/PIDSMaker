#!/usr/bin/env bash

# PostgreSQL shutdown script for Singularity/Apptainer

# Detect which container runtime is available
if command -v apptainer &> /dev/null; then
    CONTAINER_CMD="apptainer"
elif command -v singularity &> /dev/null; then
    CONTAINER_CMD="singularity"
else
    echo "ERROR: Neither apptainer nor singularity found in PATH"
    exit 1
fi

set -euo pipefail

JOB_TAG=${JOB_TAG:-${PBS_JOBID:-${SLURM_JOB_ID:-local}}}
JOB_TAG=${JOB_TAG//[^A-Za-z0-9_.-]/_}
POSTGRES_INSTANCE=${POSTGRES_INSTANCE:-postgres_${JOB_TAG}}
RUNTIME_ROOT=${RUNTIME_ROOT:-${TMPDIR:-$(pwd)}/pidsmaker-postgres-${JOB_TAG}}
PID_FILE=${POSTGRES_PID_FILE:-${PID_FILE:-${RUNTIME_ROOT}/instance.pid}}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Stopping PostgreSQL...${NC}"

STOPPED=false

# Stop only this job's instance. Never kill PostgreSQL processes from another job.
if $CONTAINER_CMD instance list | awk 'NR > 1 {print $1}' | grep -Fxq "$POSTGRES_INSTANCE"; then
    echo -e "${YELLOW}Stopping ${CONTAINER_CMD} instance: $POSTGRES_INSTANCE${NC}"
    $CONTAINER_CMD instance stop "$POSTGRES_INSTANCE"
    STOPPED=true
fi

rm -f "$PID_FILE"

if [ "$STOPPED" = true ]; then
    echo -e "${GREEN}PostgreSQL stopped${NC}"
else
    echo -e "${YELLOW}No PostgreSQL instances were found running${NC}"
fi