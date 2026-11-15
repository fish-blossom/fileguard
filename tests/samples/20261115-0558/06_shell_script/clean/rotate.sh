#!/usr/bin/env bash
set -eu
find ./logs -name '*.log' -mtime +14 -exec gzip {} \;
find ./logs -name '*.gz' -mtime +60 -delete
