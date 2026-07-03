#!/bin/sh
# Make the persistence dir writable by the unprivileged user, then drop
# privileges to run the relay. Hosts mount volumes root-owned, so we chown once
# at boot. If the dir is unset/unavailable (or DATABASE_URL is used) the relay
# just runs without a local snapshot.
set -e

DATA_DIR="${HIVE_RELAY_DATA_DIR:-}"
if [ -n "$DATA_DIR" ]; then
  mkdir -p "$DATA_DIR" 2>/dev/null || true
  chown -R hive:hive "$DATA_DIR" 2>/dev/null || true
fi

# Drop to `hive`. Prefer su-exec (alpine), then setpriv (util-linux), then su.
if command -v su-exec >/dev/null 2>&1; then
  exec su-exec hive:hive /usr/local/bin/hive-relay "$@"
elif command -v setpriv >/dev/null 2>&1; then
  exec setpriv --reuid=hive --regid=hive --init-groups /usr/local/bin/hive-relay "$@"
else
  exec su hive -c "/usr/local/bin/hive-relay $*"
fi
