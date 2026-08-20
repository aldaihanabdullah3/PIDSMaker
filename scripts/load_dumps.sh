#!/usr/bin/env bash

set -euo pipefail

DATA_DIR=${DATA_DIR:-/data}
DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}
DB_USER=${DB_USER:-postgres}
dataset=""
dump_file=""
db_override=""

usage() {
  cat <<'EOF'
Usage: load_dumps.sh [OPTIONS]

Restore all dumps, one selected dataset, or one dump file.

Options:
  --dataset NAME     Restore the dump whose target database is NAME.
  --file PATH        Restore one dump file.
  --database NAME    Override the target database name for --file.
  --data-dir PATH    Directory used when no --file is given. Default: $DATA_DIR or /data.
  --host HOST        PostgreSQL instance host. Default: $DB_HOST or localhost.
  --port PORT        PostgreSQL instance port. Default: $DB_PORT or 5432.
  --user USER        PostgreSQL user. Default: $DB_USER or postgres.
  -h, --help         Show this help.

Use --host and --port to select either PostgreSQL instance.
EOF
}

while (( $# > 0 )); do
  case "$1" in
    --dataset) dataset=${2,,}; shift 2 ;;
    --file) dump_file=${2:?"--file needs a path"}; shift 2 ;;
    --database) db_override=${2:?"--database needs a name"}; shift 2 ;;
    --data-dir) DATA_DIR=${2:?"--data-dir needs a path"}; shift 2 ;;
    --host) DB_HOST=${2:?"--host needs a value"}; shift 2 ;;
    --port) DB_PORT=${2:?"--port needs a value"}; shift 2 ;;
    --user) DB_USER=${2:?"--user needs a value"}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -n "$dataset" && -n "$dump_file" ]]; then
  echo "Use only one of --dataset and --file." >&2
  exit 2
fi
if [[ -n "$db_override" && -z "$dump_file" ]]; then
  echo "--database requires --file." >&2
  exit 2
fi
if [[ ! "$DB_PORT" =~ ^[0-9]+$ ]]; then
  echo "Invalid PostgreSQL port: $DB_PORT" >&2
  exit 2
fi

database_name() {
  local name
  name=$(basename "$1" .dump)
  case "$name" in
    optc_h201) echo "optc_201" ;;
    optc_h501) echo "optc_501" ;;
    optc_h051) echo "optc_051" ;;
    *) echo "$name" ;;
  esac
}

restore_dump() {
  local file=$1
  local db_name=${2:-$(database_name "$file")}
  local table_count final_table_count

  if [[ ! "$db_name" =~ ^[A-Za-z0-9_]+$ ]]; then
    echo "Invalid database name: $db_name" >&2
    return 2
  fi

  echo "Processing $file -> $DB_HOST:$DB_PORT/$db_name"
  if psql -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" -lqt \
      | cut -d '|' -f 1 | tr -d ' ' | grep -Fxq "$db_name"; then
    table_count=$(psql -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" -d "$db_name" \
      -Atc "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';")
    if (( table_count > 0 )); then
      echo "Database '$db_name' already has $table_count tables. Skipping restoration."
      return
    fi
  else
    psql -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" \
      -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"$db_name\";"
  fi

  pg_restore -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" \
    --clean --if-exists --no-owner --no-privileges -d "$db_name" "$file"
  final_table_count=$(psql -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" -d "$db_name" \
    -Atc "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';")
  echo "Restored '$db_name' with $final_table_count tables."
}

files=()
if [[ -n "$dump_file" ]]; then
  [[ -f "$dump_file" ]] || { echo "Dump file not found: $dump_file" >&2; exit 1; }
  files+=("$dump_file")
else
  shopt -s nullglob
  files=("$DATA_DIR"/*.dump)
  shopt -u nullglob
  (( ${#files[@]} > 0 )) || { echo "No .dump files found in $DATA_DIR" >&2; exit 1; }
fi

matched=false
for file in "${files[@]}"; do
  db_name=$(database_name "$file")
  if [[ -n "$dataset" && "$dataset" != "$db_name" && "$dataset" != "$(basename "$file" .dump)" ]]; then
    continue
  fi
  matched=true
  restore_dump "$file" "${db_override:-$db_name}"
done

$matched || { echo "No dump matched dataset '$dataset' in $DATA_DIR" >&2; exit 1; }

echo "Available databases on $DB_HOST:$DB_PORT:"
psql -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" -Atc \
  "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname;"
