#!/bin/sh
# Full disk scan script for ClamAV (portable)
# - Uses clamdscan when available (via find + xargs)
# - Falls back to clamscan if clamdscan is missing
# - Portable locking via FD 9 + flock if available, else pidfile fallback
# - Moves infected files to quarantine directory
#
# Usage: run as root (recommended) so scanner can access most files.

# ---------- Configuration ----------
LOCKFILE="/var/lock/clamav_fullscan.lock"
LOGDIR="/var/log/clamav"
LOGFILE="${LOGDIR}/fullscan-$(date +%F).log"
QUARANTINE_BASE="/var/quarantine/clamav"
QUARANTINE="${QUARANTINE_BASE}/$(date +%F_%H%M%S)"
# Top-level FS paths to exclude from scanning
EXCLUDES="/proc /sys /dev /run /tmp /var/lib/docker /var/lib/snapd /var/run/clamav /var/quarantine /sys/fs/cgroup"
# Tools (will fallback to which)
CLAMDSCAN="$(command -v clamdscan 2>/dev/null || true)"
CLAMSCAN="$(command -v clamscan 2>/dev/null || true)"
FIND="$(command -v find 2>/dev/null || /bin/find)"
XARGS="$(command -v xargs 2>/dev/null || /usr/bin/xargs)"
IONICE="$(command -v ionice 2>/dev/null || true)"
NICE="$(command -v nice 2>/dev/null || true)"
FLOCK="$(command -v flock 2>/dev/null || true)"
GREP="$(command -v grep 2>/dev/null || /bin/grep)"
SED="$(command -v sed 2>/dev/null || /bin/sed)"

# Tuning
XARGS_BATCH=1000    # number of files per clamdscan invocation via xargs
IONICE_ARGS="-c2 -n7"  # idle IO priority
NICE_ARG="-n 10"       # nice level

# ---------- Prep ----------
mkdir -p "$LOGDIR" "$QUARANTINE_BASE"
mkdir -p "$QUARANTINE"
chown root:root "$QUARANTINE"
chmod 0700 "$QUARANTINE"

# initialize LOGFILE if not exists
: >> "$LOGFILE"

# Portable lock: open FD 9 on lockfile
exec 9>"$LOCKFILE" || {
  echo "$(date '+%F %T') - ERROR: cannot open lockfile $LOCKFILE" >> "$LOGFILE"
  exit 1
}

# Try to acquire lock: prefer flock binary (advisable), else flock via shell on FD 9 if supported
if [ -n "$FLOCK" ] && [ -x "$FLOCK" ]; then
  # flock binary supports fd: flock -n 9
  $FLOCK -n 9 || {
    echo "$(date '+%F %T') - Another scan is running (flock), exiting." >> "$LOGFILE"
    exit 0
  }
else
  # Try shell builtin flock (some shells support "flock 9" style); attempt non-blocking
  if command -v flock >/dev/null 2>&1; then
    flock -n 9 || {
      echo "$(date '+%F %T') - Another scan is running (shell flock), exiting." >> "$LOGFILE"
      exit 0
    }
  else
    # Fallback to pidfile (non-atomic)
    PIDFILE="${LOCKFILE}.pid"
    if [ -f "$PIDFILE" ]; then
      pid=$(cat "$PIDFILE" 2>/dev/null)
      if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "$(date '+%F %T') - Another scan (pid $pid) is running, exiting." >> "$LOGFILE"
        exit 0
      fi
    fi
    echo $$ > "$PIDFILE"
  fi
fi

echo "$(date '+%F %T') - Starting full disk scan" >> "$LOGFILE"

# Check clamdscan/clamscan availability
USE_CLAMD=0
if [ -n "$CLAMDSCAN" ] && [ -x "$CLAMDSCAN" ]; then
  USE_CLAMD=1
  echo "$(date '+%F %T') - Using clamdscan at $CLAMDSCAN" >> "$LOGFILE"
elif [ -n "$CLAMSCAN" ] && [ -x "$CLAMSCAN" ]; then
  USE_CLAMD=0
  echo "$(date '+%F %T') - clamdscan not found, falling back to clamscan at $CLAMSCAN" >> "$LOGFILE"
else
  echo "$(date '+%F %T') - ERROR: Neither clamdscan nor clamscan found in PATH. Install clamav." >> "$LOGFILE"
  # release lock and exit
  if [ -z "$FLOCK" ]; then [ -f "${LOCKFILE}.pid" ] && rm -f "${LOCKFILE}.pid"; fi
  exec 9>&-
  exit 1
fi

# Helper: is path excluded?
is_excluded() {
  target="$1"
  for ex in $EXCLUDES; do
    [ "$target" = "$ex" ] && return 0
  done
  return 1
}

# Iterate top-level dirs
for dir in /*; do
  # skip excluded and non-directories
  if is_excluded "$dir"; then
    echo "$(date '+%F %T') - Skipping excluded $dir" >> "$LOGFILE"
    continue
  fi
  [ ! -d "$dir" ] && continue

  echo "$(date '+%F %T') - Scanning $dir" >> "$LOGFILE"

  if [ "$USE_CLAMD" -eq 1 ]; then
    # Use find + xargs -> clamdscan (no reliance on -r)
    # Ensure find and xargs exist
    if [ ! -x "$FIND" ] || [ ! -x "$XARGS" ]; then
      echo "$(date '+%F %T') - ERROR: find or xargs not found, skipping $dir" >> "$LOGFILE"
      continue
    fi

    # Build command prefix with ionice/nice if available
    CMD_PREFIX=""
    if [ -n "$IONICE" ] && [ -x "$IONICE" ]; then
      CMD_PREFIX="$CMD_PREFIX $IONICE $IONICE_ARGS"
    fi
    if [ -n "$NICE" ] && [ -x "$NICE" ]; then
      CMD_PREFIX="$CMD_PREFIX $NICE $NICE_ARG"
    fi

    # run: find ... -print0 | xargs -0 -n $XARGS_BATCH clamdscan --fdpass --no-summary --log="$LOGFILE"
    # note: wrap in sh -c to apply prefix
    $FIND "$dir" -type f -print0 \
      | $XARGS -0 -r -n "$XARGS_BATCH" sh -c "$CMD_PREFIX $CLAMDSCAN --fdpass --no-summary --log='$LOGFILE' \"\$@\"" _

  else
    # Fallback: use clamscan recursive (may be slower)
    CMD="$CLAMSCAN -r --no-summary --log=\"$LOGFILE\" \"$dir\""
    if [ -n "$IONICE" ] && [ -x "$IONICE" ]; then
      CMD="$IONICE $IONICE_ARGS $CMD"
    fi
    if [ -n "$NICE" ] && [ -x "$NICE" ]; then
      CMD="$NICE $NICE_ARG $CMD"
    fi
    # Execute
    sh -c "$CMD"
  fi
done

# Parse log for FOUND entries and move infected files to quarantine
# clamdscan/clamscan log line format: /path/to/file: MalwareName FOUND
# Use grep to find lines ending with FOUND
if [ -f "$LOGFILE" ]; then
  $GREP "FOUND$" "$LOGFILE" | while IFS= read -r line; do
    # extract filepath (strip ': <name> FOUND')
    filepath=$($SED -E 's/: .*FOUND$//' <<EOF
$line
EOF
)
    # If filepath contains trailing whitespace, trim
    filepath=$(printf '%s' "$filepath" | sed -e 's/[[:space:]]*$//')
    if [ -z "$filepath" ]; then
      echo "$(date '+%F %T') - Warning: cannot parse infected path from log line: $line" >> "$LOGFILE"
      continue
    fi

    if [ -e "$filepath" ]; then
      base=$(basename "$filepath")
      safe_name="$(date +%s)-$$-$base"
      # Ensure quarantine dir exists (it was created at top, but ensure)
      mkdir -p "$QUARANTINE"
      chown root:root "$QUARANTINE"
      chmod 0700 "$QUARANTINE"
      # Move file to quarantine (preserve by renaming)
      if mv -f -- "$filepath" "$QUARANTINE/$safe_name" 2>/dev/null; then
        echo "$(date '+%F %T') - QUARANTINED: $filepath -> $QUARANTINE/$safe_name" >> "$LOGFILE"
      else
        echo "$(date '+%F %T') - ERROR: Failed to quarantine $filepath" >> "$LOGFILE"
      fi
    else
      echo "$(date '+%F %T') - Note: logged infected file not present on disk: $filepath" >> "$LOGFILE"
    fi
  done
else
  echo "$(date '+%F %T') - Logfile $LOGFILE not found, nothing to parse" >> "$LOGFILE"
fi

echo "$(date '+%F %T') - Full disk scan finished" >> "$LOGFILE"

# Cleanup fallback pidfile if used
if [ ! -x "$FLOCK" ]; then
  [ -f "${LOCKFILE}.pid" ] && rm -f "${LOCKFILE}.pid"
fi

# release lock: close fd 9
exec 9>&-

exit 0
