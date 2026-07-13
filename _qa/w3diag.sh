#!/bin/bash
cd /c/Users/User/Downloads/sd
op="$1"; k="${2:-4}"
grep -E "warning C4047: '$op'" _qa/w3/w3.log | head -$k | while read line; do
  fn=$(echo "$line" | grep -oE '^[a-zA-Z0-9_]+\.c'); ln=$(echo "$line" | grep -oE '\([0-9]+\)' | head -1 | tr -d '()')
  msg=$(echo "$line" | grep -oE "differs.*")
  echo "[$fn:$ln] $msg"
  sed -n "${ln}p" "_qa/w3/$fn" 2>/dev/null | sed 's/^ *//' | cut -c1-140
done
