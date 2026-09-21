#!/bin/bash
# Sample chrome RSS + system available memory while the page runs.
peak=0
for i in $(seq 1 3000); do
  rss=$(ps -o rss= -C chrome 2>/dev/null | awk '{s+=$1} END {print s+0}')
  avail=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)
  [ "$rss" -gt "$peak" ] && peak=$rss
  echo "$(date +%T) chrome_rss_mb=$((rss/1024)) peak_mb=$((peak/1024)) sys_avail_mb=$avail"
  grep -q "__DONE__" /tmp/verify-server.log 2>/dev/null && break
  sleep 5
done
