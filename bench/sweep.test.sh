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
[ "$(grep -c '^sweep: reclaimed' <<<"$out")" -eq 10 ] || fail "expected 10 reclaim lines (5 arns x 2 regions)" "$out"
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
[ "$(grep -c '^LEFTOVER: orphaned resource' <<<"$out")" -eq 2 ] || fail "expected 2 leftover lines (1 arn x 2 regions)" "$out"
grep -q 'nat-1 (ap-northeast-1)' <<<"$out" || fail "arn/region not reported" "$out"

# 削除が失敗したものは LEFTOVER に落ちる
printf 'arn:aws:cognito-idp:ap-northeast-1:1:userpool/ap-northeast-1_abc\n' > "$tmp/failing"
export CDKPF_STUB_FAIL=delete-user-pool
out=$(run "$tmp/failing")
unset CDKPF_STUB_FAIL
[ "$(grep -c '^LEFTOVER: orphaned resource' <<<"$out")" -eq 2 ] || fail "a failed deletion was not reported" "$out"
grep -q 'could not delete: .*stub refused' <<<"$out" || fail "the failure reason was not carried onto the leftover line" "$out"

# 既に消えているものは回収済み扱い（タグ索引の残骸で毎月 LEFTOVER が出るのを防ぐ）
export CDKPF_STUB_FAIL=delete-user-pool CDKPF_STUB_ERR='An error occurred (ResourceNotFoundException) when calling the DeleteUserPool operation: User pool does not exist'
out=$(run "$tmp/failing")
unset CDKPF_STUB_FAIL CDKPF_STUB_ERR
grep -q LEFTOVER <<<"$out" && fail "an already-deleted resource was reported as leftover" "$out"

echo "sweep.test.sh: OK"
