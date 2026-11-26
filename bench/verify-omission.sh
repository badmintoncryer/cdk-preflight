#!/bin/bash
# ③ 反証工程の実測: ルールの「このプロパティを省略するとデプロイが落ちる」という主張を実機で確かめる。
# scripts/omission-sweep.ts --emit-mutants で主張ごとの写し（fail = pass テンプレートからそのプロパティを
# 抜いたもの）を作り、bench/verify-rule.sh --fail-only を並列に回す。
#
# 使い方: bash bench/verify-omission.sh <rule-id ...>   （並列数はルール単位で CDKPF_JOBS、既定 4。pass も作るなら CDKPF_OMIT_FULL=1）
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
# 同じルールの写しは pass テンプレートを共有するので、物理名（ドメイン名、ゲートウェイ名など）も同じになる。
# 並列に作ると互いの "already exists" で倒れ、制約の証拠にならない（2026-11-26、opensearch / eks /
# networkfirewall / agentcore / athena の 15 本がこれで判定不能）。並列はルール単位にし、写しは順に回す。
# CDKPF_OMIT_FULL=1 のときは pass も作る（--fail-only を外す）: pass が通って写しだけが倒れたことまで見る。
export MODE=--fail-only
[ "${CDKPF_OMIT_FULL:-}" = 1 ] && MODE=
# shellcheck disable=SC2016
cut -f2 "$OUT/claims.tsv" | sort -u | xargs -P "${CDKPF_JOBS:-4}" -I{} bash -c '
  for copy in $(awk -F"\t" -v r="$1" "\$2 == r {print \$1}" "$OUT/claims.tsv"); do
    CDKPF_RULES_DIR="$OUT" bash bench/verify-rule.sh "$copy" $MODE >/dev/null 2>&1
    rc=$?
    line=$(awk -F"\t" -v id="$copy" "\$1 == id" "$OUT/claims.tsv")
    reason=$(sed -nE "s/^fail: reason=//p" "bench/logs/$copy.log" | tail -1 | tr "\t\n" "  " | cut -c1-2000)
    printf "%s\t%s\t%s\n" "$line" "$rc" "$reason" >> "$RES"
    echo "$copy -> $rc"
  done
' _ {}
sort -o "$RES" "$RES"
echo "-- $(wc -l < "$RES") claims: $(cut -f4 "$RES" | sort | uniq -c | tr '\n' ' ')"
echo "-- results: $RES"
