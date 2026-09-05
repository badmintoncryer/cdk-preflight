#!/bin/bash
# sweep.sh の残骸検知の自己チェック。aws をスタブに差し替えて実際の API は叩かない。
# 使い方: bash bench/sweep.test.sh
set -u
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/aws" <<'STUB'
#!/bin/bash
case "$1 $2" in
  "cloudformation list-stacks") echo "" ;;
  "resourcegroupstaggingapi get-resources") cat "$CDKPF_STUB_ORPHANS" ;;
  *) echo "unexpected stub call: $*" >&2; exit 1 ;;
esac
STUB
chmod +x "$tmp/aws"
export PATH="$tmp:$PATH"

: > "$tmp/none"
export CDKPF_STUB_ORPHANS="$tmp/none"
out=$(bash bench/sweep.sh)
grep -q LEFTOVER <<<"$out" && { echo "FAIL: clean account reported a leftover"; exit 1; }

printf 'arn:aws:ec2:ap-northeast-1:1:natgateway/nat-1\tarn:aws:rds:ap-northeast-1:1:db:d1\n' > "$tmp/some"
export CDKPF_STUB_ORPHANS="$tmp/some"
out=$(bash bench/sweep.sh)
[ "$(grep -c '^LEFTOVER: orphaned resource' <<<"$out")" -eq 4 ] || { echo "FAIL: expected 4 orphan lines (2 arns x 2 regions), got:"; echo "$out"; exit 1; }
grep -q 'nat-1 (ap-northeast-1)' <<<"$out" || { echo "FAIL: arn/region not reported"; exit 1; }

echo "sweep.test.sh: OK"
