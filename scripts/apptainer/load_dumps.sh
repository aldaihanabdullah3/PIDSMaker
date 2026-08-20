#!/usr/bin/env bash

# postgres-start.sh binds the shared implementation from the parent scripts directory.
exec /scripts/load_dumps-common.sh "$@"
