#!/usr/bin/env bash

# PostgreSQL status script for Singularity/Apptainer

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
RUN_DIR=${POSTGRES_RUN_DIR:-${RUN_DIR:-${RUNTIME_ROOT}/run}}
PID_FILE=${POSTGRES_PID_FILE:-${PID_FILE:-${RUNTIME_ROOT}/instance.pid}}
SOCKET_PATH=${RUN_DIR}/.s.PGSQL.5432

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}PostgreSQL Status:${NC}"

# Check multiple ways to detect if PostgreSQL is running
POSTGRES_RUNNING=false

# Method 1: Check PID file
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 $PID 2>/dev/null; then
        echo -e "${GREEN}✓ PostgreSQL process is running (PID: $PID)${NC}"
        POSTGRES_RUNNING=true
    else
        echo -e "${YELLOW}! PID file exists but process is not running${NC}"
        rm -f "$PID_FILE"
    fi
fi

# Method 2: Check this job's instance and Unix socket.
if $CONTAINER_CMD instance list | awk 'NR > 1 {print $1}' | grep -Fxq "$POSTGRES_INSTANCE" && \
   $CONTAINER_CMD exec instance://$POSTGRES_INSTANCE \
         pg_isready -h /var/run/postgresql -U postgres > /dev/null 2>&1; then
    echo -e "${GREEN}✓ PostgreSQL is accepting connections${NC}"
    echo -e "${GREEN}  Instance: ${POSTGRES_INSTANCE}${NC}"
     echo -e "${GREEN}  Unix socket: ${SOCKET_PATH}${NC}"
    POSTGRES_RUNNING=true
    
    # Show database list
    echo -e "${YELLOW}Databases:${NC}"
    $CONTAINER_CMD exec instance://$POSTGRES_INSTANCE \
        psql -h /var/run/postgresql -U postgres -c "\l" 2>/dev/null | \
        grep -v template | grep -v "^-" | grep -v "^(" | grep -v "Name.*Owner" | \
        grep -v "^\s*$" | head -10
    
    # Show PostgreSQL version
    echo -e "${YELLOW}Version:${NC}"
    $CONTAINER_CMD exec instance://$POSTGRES_INSTANCE \
        psql -h /var/run/postgresql -U postgres \
        -c "SELECT version();" -t 2>/dev/null | head -1
    
else
    echo -e "${RED}✗ PostgreSQL is not accepting connections${NC}"
fi

# Method 3: Check this job's host-side Unix socket.
if [ -S "$SOCKET_PATH" ]; then
    echo -e "${GREEN}✓ Unix socket exists: ${SOCKET_PATH}${NC}"
    POSTGRES_RUNNING=true
else
    echo -e "${RED}✗ Unix socket does not exist: ${SOCKET_PATH}${NC}"
fi

# Final status
if [ "$POSTGRES_RUNNING" = true ]; then
    echo -e "${GREEN}Overall Status: PostgreSQL is running and accessible${NC}"
    exit 0
else
    echo -e "${RED}Overall Status: PostgreSQL is not running or not accessible${NC}"
    exit 1
fi