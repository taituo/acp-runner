#!/bin/sh
# Exit 0 when add.sh is correct.
set -e
out=$(sh "$(dirname "$0")/add.sh" 2 3)
if [ "$out" = "5" ]; then echo PASS; exit 0; fi
echo "FAIL: expected 5, got $out"; exit 1
