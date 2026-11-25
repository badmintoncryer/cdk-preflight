#!/bin/bash
# ③ 反証工程の実測: ルールの「このプロパティを省略するとデプロイが落ちる」という主張を実機で確かめる。
# scripts/omission-sweep.ts --emit-mutants で主張ごとの写し（fail = pass テンプレートからそのプロパティを
# 抜いたもの）を作り、bench/verify-rule.sh --fail-only を並列に回す。
#
# 使い方: bash bench/verify-omission.sh <rule-id ...>   （並列数は CDKPF_JOBS、既定 4）
# 結果: bench/logs/omission-results.tsv  <copy-id> <rule-id> <key> <exit> <reason>
#   exit 0 = 落ちた（主張は正しい: key を meta.omissionFails へ、reason を repro.evidence へ）
#   exit 2 = 通った（主張は誤り: ルールが省略を値として読んでいる。ルールを直す）
#   exit 4 = 判定不能（足場の失敗など。ログを見る）
set -u
cd "$(dirname "$0")/.."
[ $# -gt 0 ] || { echo "usage: verify-omission.sh <rule-id ...>"; exit 1; }
OUT=$(mktemp -d "${TMPDIR:-/tmp}/cdkpf-omit-XXXXXX")
npx projen bundle-rules >/dev/null
npx ts-node --transpile-only --project test/tsconfig.json scripts/omission-sweep.ts --emit-mutants "$OUT" "$@" || exit 1
mkdir -p bench/logs
RES=bench/logs/omission-results.tsv
: > "$RES"
export OUT RES
# shellcheck disable=SC2016
cut -f1 "$OUT/claims.tsv" | xargs -P "${CDKPF_JOBS:-4}" -I{} bash -c '
  CDKPF_RULES_DIR="$OUT" bash bench/verify-rule.sh "$1" --fail-only >/dev/null 2>&1
  rc=$?
  line=$(awk -F"\t" -v id="$1" "\$1 == id" "$OUT/claims.tsv")
  reason=$(sed -nE "s/^fail: reason=//p" "bench/logs/$1.log" | tail -1 | tr "\t\n" "  " | cut -c1-600)
  printf "%s\t%s\t%s\n" "$line" "$rc" "$reason" >> "$RES"
  echo "$1 -> $rc"
' _ {}
sort -o "$RES" "$RES"
echo "-- $(wc -l < "$RES") claims: $(cut -f4 "$RES" | sort | uniq -c | tr '\n' ' ')"
echo "-- results: $RES"
