#!/bin/bash
# report.sh の集計の自己チェック。gh をスタブに差し替え、一時ディレクトリに組んだ rules/ と
# bench/out/ だけを読ませるので、issue は立たず、手元の結果も上書きしない。
# 使い方: bash bench/report.test.sh
set -u
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bench/out" "$tmp/rules/t/pf-t-a" "$tmp/rules/t/pf-t-b" "$tmp/bin"
cp "$root/bench/report.sh" "$tmp/bench/"
printf '#!/bin/bash\necho "gh $*" >> "%s/gh.calls"\n' "$tmp" > "$tmp/bin/gh"
chmod +x "$tmp/bin/gh"
fail() { echo "FAIL: $1"; cat "$tmp/out"; exit 1; }

# pf-t-b の行が無い（そのシャードが落ちた）。計画を渡せば INCONCLUSIVE として数え、issue を立てる
echo '{"rule":"pf-t-a","service":"t","status":"OK","region":"us-east-1","detail":""}' > "$tmp/bench/out/t.1of2.jsonl"
PATH="$tmp/bin:$PATH" CDKPF_PLAN='["t.1of2","t.2of2"]' bash "$tmp/bench/report.sh" > "$tmp/out" 2>&1
grep -q 'pf-t-b.*no result' "$tmp/out" || fail "a planned rule without a result row must be reported"
grep -q 'gh issue create' "$tmp/gh.calls" 2>/dev/null || fail "a missing shard must file the issue, not read as all green"

# verify-rule.sh の retain 削除の残骸は OK の行の detail にしか無い。LEFTOVER として拾う
rm -f "$tmp/gh.calls"
echo '{"rule":"pf-t-a","service":"t","status":"OK","region":"us-east-1","detail":"LEFTOVER: bucket cdkpf-x "}' > "$tmp/bench/out/t.1of2.jsonl"
echo '{"rule":"pf-t-b","service":"t","status":"OK","region":"us-east-1","detail":""}' > "$tmp/bench/out/t.2of2.jsonl"
PATH="$tmp/bin:$PATH" CDKPF_PLAN='["t.1of2","t.2of2"]' bash "$tmp/bench/report.sh" > "$tmp/out" 2>&1
grep -q 'pf-t-a: LEFTOVER: bucket cdkpf-x' "$tmp/out" || fail "a LEFTOVER line in an OK row must be reported"
grep -q 'gh issue create' "$tmp/gh.calls" 2>/dev/null || fail "a LEFTOVER must file the issue"

# 全部そろって何も無ければ issue は立てない
rm -f "$tmp/gh.calls"
echo '{"rule":"pf-t-a","service":"t","status":"OK","region":"us-east-1","detail":""}' > "$tmp/bench/out/t.1of2.jsonl"
PATH="$tmp/bin:$PATH" CDKPF_PLAN='["t.1of2","t.2of2"]' bash "$tmp/bench/report.sh" > "$tmp/out" 2>&1
grep -q 'all green' "$tmp/out" || fail "a complete green run must say all green"
[ ! -e "$tmp/gh.calls" ] || fail "a complete green run must not file an issue"

echo "report.test.sh: OK"
