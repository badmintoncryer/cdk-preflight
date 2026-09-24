#!/bin/bash
# sweep.sh の残骸回収の自己チェック。aws をスタブに差し替えて実際の API は叩かない。
# 使い方: bash bench/sweep.test.sh
set -u
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/aws" <<'STUB'
#!/bin/bash
echo "$*" >> "$CDKPF_STUB_CALLS"
case "$1 $2" in
  "cloudformation list-stacks") echo "" ;;
  "resourcegroupstaggingapi get-resources") cat "$CDKPF_STUB_ORPHANS" ;;
  "kms describe-key") echo "${CDKPF_STUB_KEYSTATE:-Enabled}" ;;
  "route53resolver list-firewall-rule-groups") echo "${CDKPF_STUB_FRG:-}" ;;
  "route53resolver list-firewall-rule-group-associations") echo "${CDKPF_STUB_FRGA:-}" ;;
  "route53resolver list-firewall-rules") printf '%b\n' "${CDKPF_STUB_FR:-}" ;;
  "route53resolver list-firewall-domain-lists") echo "${CDKPF_STUB_FDL:-}" ;;
  "globalaccelerator list-accelerators") echo "${CDKPF_STUB_GA:-}" ;;
  "globalaccelerator list-custom-routing-accelerators") echo "${CDKPF_STUB_GACR:-}" ;;
  "globalaccelerator list-listeners") echo "${CDKPF_STUB_GAL:-}" ;;
  "globalaccelerator list-endpoint-groups") echo "${CDKPF_STUB_GAEG:-}" ;;
  "globalaccelerator describe-accelerator") echo "${CDKPF_STUB_GASTATUS:-DEPLOYED}" ;;
  *)
    if [ -n "${CDKPF_STUB_FAIL:-}" ] && grep -q -- "$CDKPF_STUB_FAIL" <<<"$*"; then
      echo "${CDKPF_STUB_ERR:-An error occurred: stub refused $2}" >&2; exit 254
    fi
    exit 0 ;;
esac
STUB
chmod +x "$tmp/aws"
export PATH="$tmp:$PATH"
export CDKPF_STUB_CALLS="$tmp/calls"

run() { # run <orphans-file> — sweep を 1 回まわし、出力を返す。呼び出しログは $tmp/calls
  export CDKPF_STUB_ORPHANS="$1"
  : > "$CDKPF_STUB_CALLS"
  bash bench/sweep.sh
}
fail() { echo "FAIL: $1"; echo "--- out ---"; echo "${2:-}"; echo "--- calls ---"; cat "$CDKPF_STUB_CALLS"; exit 1; }
called() { grep -q -- "$1" "$CDKPF_STUB_CALLS"; }

: > "$tmp/none"
out=$(run "$tmp/none")
grep -q LEFTOVER <<<"$out" && fail "clean account reported a leftover" "$out"

# 既知の種別は回収され、LEFTOVER に落ちない
printf 'arn:aws:ecs:ap-northeast-1:1:cluster/c1\tarn:aws:ecs:ap-northeast-1:1:task-definition/t1:1\tarn:aws:cognito-idp:ap-northeast-1:1:userpool/ap-northeast-1_abc\tarn:aws:kms:ap-northeast-1:1:key/k1\tarn:aws:dynamodb:ap-northeast-1:1:table/tbl1/stream/2026-09-06T11:32:34.629\n' > "$tmp/known"
out=$(run "$tmp/known")
grep -q LEFTOVER <<<"$out" && fail "a reclaimable orphan was reported as leftover" "$out"
[ "$(grep -c '^sweep: reclaimed' <<<"$out")" -eq 15 ] || fail "expected 15 reclaim lines (5 arns x 3 regions)" "$out"
called 'ecs delete-cluster --cluster arn:aws:ecs:ap-northeast-1:1:cluster/c1' || fail "cluster not deleted"
called 'ecs delete-task-definitions --task-definitions arn:aws:ecs:ap-northeast-1:1:task-definition/t1:1' || fail "task definition not deleted"
called 'cognito-idp delete-user-pool --user-pool-id ap-northeast-1_abc' || fail "user pool not deleted"
called 'kms schedule-key-deletion --key-id arn:aws:kms:ap-northeast-1:1:key/k1 --region ap-northeast-1 --pending-window-in-days 7' || fail "key deletion not scheduled"
called 'dynamodb delete-table --table-name tbl1' || fail "table not deleted (stream arn must resolve to its table)"

# 削除待ちの KMS キーは二度スケジュールせず、LEFTOVER にも落とさない
printf 'arn:aws:kms:ap-northeast-1:1:key/k1\n' > "$tmp/pending"
export CDKPF_STUB_KEYSTATE=PendingDeletion
out=$(run "$tmp/pending")
unset CDKPF_STUB_KEYSTATE
grep -q LEFTOVER <<<"$out" && fail "a key already pending deletion was reported as leftover" "$out"
called 'schedule-key-deletion' && fail "re-scheduled a key that is already pending deletion" "$out"

# 未知の種別は今まで通り LEFTOVER で報告する
printf 'arn:aws:ec2:ap-northeast-1:1:natgateway/nat-1\n' > "$tmp/unknown"
out=$(run "$tmp/unknown")
[ "$(grep -c '^LEFTOVER: orphaned resource' <<<"$out")" -eq 3 ] || fail "expected 3 leftover lines (1 arn x 3 regions)" "$out"
grep -q 'nat-1 (ap-northeast-1)' <<<"$out" || fail "arn/region not reported" "$out"

# 削除が失敗したものは LEFTOVER に落ちる
printf 'arn:aws:cognito-idp:ap-northeast-1:1:userpool/ap-northeast-1_abc\n' > "$tmp/failing"
export CDKPF_STUB_FAIL=delete-user-pool
out=$(run "$tmp/failing")
unset CDKPF_STUB_FAIL
[ "$(grep -c '^LEFTOVER: orphaned resource' <<<"$out")" -eq 3 ] || fail "a failed deletion was not reported" "$out"
grep -q 'could not delete: .*stub refused' <<<"$out" || fail "the failure reason was not carried onto the leftover line" "$out"

# 既に消えているものは回収済み扱い（タグ索引の残骸で毎月 LEFTOVER が出るのを防ぐ）
export CDKPF_STUB_FAIL=delete-user-pool CDKPF_STUB_ERR='An error occurred (ResourceNotFoundException) when calling the DeleteUserPool operation: User pool does not exist'
out=$(run "$tmp/failing")
unset CDKPF_STUB_FAIL CDKPF_STUB_ERR
grep -q LEFTOVER <<<"$out" && fail "an already-deleted resource was reported as leftover" "$out"

# CloudFormation が消し残す DNS Firewall の残骸を、参照される順に消す
export CDKPF_STUB_FRG=rg-1 CDKPF_STUB_FRGA=ra-1 CDKPF_STUB_FR='dl-1\tA\ndl-2\tNone' CDKPF_STUB_FDL=dl-1
out=$(run "$tmp/none")
grep -q LEFTOVER <<<"$out" && fail "a reclaimable firewall orphan was reported as leftover" "$out"
[ "$(grep -c 'reclaimed orphaned firewall' <<<"$out")" -eq 6 ] || fail "expected 6 firewall reclaim lines (group + list x 3 regions)" "$out"
called 'disassociate-firewall-rule-group --firewall-rule-group-association-id ra-1' || fail "association not removed"
# qtype 付きのルールは --qtype まで渡さないと消えない。qtype 無しの行に --qtype を付けても落ちる
called 'delete-firewall-rule --firewall-rule-group-id rg-1 --firewall-domain-list-id dl-1 --qtype A' || fail "qtype not passed through"
called 'delete-firewall-rule --firewall-rule-group-id rg-1 --firewall-domain-list-id dl-2 --region' || fail "qtype-less rule not deleted plainly"
[ "$(grep -n 'delete-firewall-rule --' "$CDKPF_STUB_CALLS" | head -1 | cut -d: -f1)" \
  -lt "$(grep -n 'delete-firewall-rule-group --' "$CDKPF_STUB_CALLS" | head -1 | cut -d: -f1)" ] ||
  fail "rules must be deleted before the group ([RSLVR-02103])" "$out"

export CDKPF_STUB_FAIL=delete-firewall-domain-list
out=$(run "$tmp/none")
unset CDKPF_STUB_FAIL CDKPF_STUB_FRG CDKPF_STUB_FRGA CDKPF_STUB_FR CDKPF_STUB_FDL
[ "$(grep -c '^LEFTOVER: orphaned firewall domain list' <<<"$out")" -eq 3 ] || fail "a failed firewall deletion was not reported" "$out"

# Global Accelerator は時間課金（有効・無効に関わらず $0.025/h）で、リージョンループにもタグ索引にも
# 載らない。依存の順（endpoint group → listener → accelerator）に消し、削除前に無効化する
export CDKPF_STUB_GA=ga-1 CDKPF_STUB_GAL=lsn-1 CDKPF_STUB_GAEG=eg-1
out=$(run "$tmp/none")
grep -q LEFTOVER <<<"$out" && fail "a reclaimable accelerator was reported as leftover" "$out"
[ "$(grep -c 'reclaimed orphaned accelerator' <<<"$out")" -eq 1 ] || fail "expected 1 accelerator reclaim line (GA is global, not per region)" "$out"
called 'globalaccelerator delete-endpoint-group --endpoint-group-arn eg-1' || fail "endpoint group not deleted"
called 'globalaccelerator delete-listener --listener-arn lsn-1' || fail "listener not deleted"
called 'globalaccelerator update-accelerator --accelerator-arn ga-1 --no-enabled' || fail "accelerator not disabled before delete"
[ "$(grep -n 'globalaccelerator delete-listener' "$CDKPF_STUB_CALLS" | head -1 | cut -d: -f1)" \
  -lt "$(grep -n 'globalaccelerator delete-accelerator' "$CDKPF_STUB_CALLS" | head -1 | cut -d: -f1)" ] ||
  fail "listeners must be deleted before the accelerator" "$out"
[ "$(grep -n 'update-accelerator .*--no-enabled' "$CDKPF_STUB_CALLS" | head -1 | cut -d: -f1)" \
  -lt "$(grep -n 'globalaccelerator delete-accelerator' "$CDKPF_STUB_CALLS" | head -1 | cut -d: -f1)" ] ||
  fail "an enabled accelerator cannot be deleted; disable must come first" "$out"

# 消せなかった accelerator は時間課金なので LEFTOVER に落として金額まで出す
export CDKPF_STUB_FAIL=delete-accelerator
out=$(run "$tmp/none")
unset CDKPF_STUB_FAIL
grep -q 'LEFTOVER: orphaned accelerator ga-1 (us-west-2, \$0.025/h)' <<<"$out" || fail "a failed accelerator deletion was not reported with its hourly cost" "$out"
unset CDKPF_STUB_GA CDKPF_STUB_GAL CDKPF_STUB_GAEG

# カスタムルーティングは自動削除しないが、見えなくはしない
export CDKPF_STUB_GACR=cr-1
out=$(run "$tmp/none")
unset CDKPF_STUB_GACR
grep -q 'LEFTOVER: orphaned custom routing accelerator cr-1' <<<"$out" || fail "a custom routing accelerator was not reported" "$out"

echo "sweep.test.sh: OK"
