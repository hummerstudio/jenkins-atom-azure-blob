#!/usr/bin/env bash
# The signature is recomputed by the endpoint: a wrong canonical string fails here, not in production.
set -uo pipefail
cd "$(dirname "$0")/.."
./build.sh >/dev/null || { echo "build failed" >&2; exit 1; }
. tools/smoke-lib.sh

account="devstoreaccount1"
key="$(printf 'the-test-account-key-0123456789' | base64)"
log="$(mktemp)"; port=$((21000 + RANDOM % 900))
python3 tools/fake_blob.py "$port" "$log" "$account" "$key" & server=$!
trap 'kill $server 2>/dev/null; wait $server 2>/dev/null' EXIT
for _ in $(seq 1 40); do curl -s -o /dev/null "http://127.0.0.1:$port/" && break; sleep 0.1; done

ws="$(mktemp -d)"; mkdir -p "$ws/build/libs"
printf 'jar-bytes' >"$ws/build/libs/app-1.0.0.jar"

cat >"$ws/input.json" <<EOF
{"account": "$account", "container": "artifacts",
 "endpoint": "http://127.0.0.1:$port", "files": "build/libs/*.jar", "blobPrefix": "1.0.0"}
EOF
printf '{"accountKey": "%s"}' "$key" >"$ws/.secrets.json"
run "$ws" >"$ws/atom.log" 2>&1 || fail "upload failed: $(cat "$ws/output.json")"
[ "$(output "$ws" uploaded)" = "1" ] || fail "uploaded count: $(cat "$ws/output.json")"
[ "$(output "$ws" bytes)" = "9" ] || fail "bytes: $(cat "$ws/output.json")"
python3 - "$log" <<'PY' || fail "the endpoint rejected the signature: $(tail -1 "$log")"
import json, sys
line = json.loads(open(sys.argv[1]).read().strip().splitlines()[-1])
assert line["signatureOk"], line["canonical"]
assert line["path"] == "/artifacts/1.0.0/app-1.0.0.jar", line["path"]
assert line["blobType"] == "BlockBlob", line["blobType"]
PY

# without a blobPrefix the relative path is kept
: >"$log"
cat >"$ws/input.json" <<EOF
{"account": "$account", "container": "artifacts",
 "endpoint": "http://127.0.0.1:$port", "files": "build/libs/*.jar"}
EOF
printf '{"accountKey": "%s"}' "$key" >"$ws/.secrets.json"
run "$ws" >"$ws/atom.log" 2>&1 || fail "upload without prefix failed"
python3 - "$log" <<'PY' || fail "path: $(tail -1 "$log")"
import json, sys
line = json.loads(open(sys.argv[1]).read().strip().splitlines()[-1])
assert line["path"] == "/artifacts/build/libs/app-1.0.0.jar", line["path"]
assert line["signatureOk"], "signature"
PY

# overwrite=false adds the precondition header
: >"$log"
cat >"$ws/input.json" <<EOF
{"account": "$account", "container": "artifacts", "overwrite": "false",
 "endpoint": "http://127.0.0.1:$port", "files": "build/libs/*.jar"}
EOF
printf '{"accountKey": "%s"}' "$key" >"$ws/.secrets.json"
run "$ws" >"$ws/atom.log" 2>&1 || fail "overwrite=false run failed"
grep -q '"ifNoneMatch": "\*"' "$log" || fail "If-None-Match missing: $(tail -1 "$log")"

# a wrong key is the caller's problem, and the message carries Azure's answer
kill $server 2>/dev/null; wait $server 2>/dev/null
cat >"$ws/input.json" <<EOF
{"account": "$account", "container": "artifacts",
 "endpoint": "http://127.0.0.1:$port", "files": "build/libs/*.jar"}
EOF
printf '{"accountKey": "%s"}' "$(printf 'wrong-key' | base64)" >"$ws/.secrets.json"
python3 tools/fake_blob.py "$port" "$log" "$account" "$key" & server=$!
for _ in $(seq 1 40); do curl -s -o /dev/null "http://127.0.0.1:$port/" && break; sleep 0.1; done
run "$ws" >"$ws/atom.log" 2>&1 && fail "a wrong key must fail the step"
grep -q "HTTP 403" "$ws/output.json" || fail "403 not reported: $(cat "$ws/output.json")"
grep -q '"errorType":1' "$ws/output.json" || fail "403 should be USER(1): $(cat "$ws/output.json")"

# missing credentials
cat >"$ws/input.json" <<EOF
{"account": "$account", "container": "artifacts", "files": "build/libs/*.jar"}
EOF
run "$ws" >"$ws/atom.log" 2>&1 && fail "missing key must be refused"
grep -q "accountKey is required" "$ws/output.json" || fail "message: $(cat "$ws/output.json")"

echo "smoke ok: signature recomputed, blob path, If-None-Match, wrong key 403, missing credentials"
