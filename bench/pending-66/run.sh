#!/bin/bash
# #66 の実機ゲート一括ランナー（AWS 認証がある環境で回す）。
# 使い方: bash run.sh <repo-dir> <pending.txt> [--fail-only]
#   <repo-dir>  : cdk-preflight のチェックアウト（ルールがマージ済みのブランチ）
#   <pending.txt>: 1 行 1 rule id。行末に `fail-only` と書くとそのルールだけ fail-only
# 出力: bench-out/<rule-id>.log（verify-rule.sh のログ写し）、bench-out/summary.tsv（1 ルール 1 行）
# exit 0 のルールは meta.yaml の `bench: PENDING...` を実測行に置き換える。
# exit 2（BROKEN-EXPECTATION）/ 3 / 4 は summary に残すだけで meta.yaml は触らない（人が判断する）。
set -u
REPO="${1:?repo dir}"; LIST="${2:?pending list}"; MODE="${3:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/bench-out"; mkdir -p "$OUT"
SUMMARY="$OUT/summary.tsv"; touch "$SUMMARY"
REGION="${CDKPF_REGION:-us-east-1}"
TODAY="$(date +%F)"
while read -r rule flag _; do
  [ -z "$rule" ] && continue; case "$rule" in \#*) continue ;; esac
  grep -q "^$rule	" "$SUMMARY" && { echo "skip (done): $rule"; continue; }
  fo="$MODE"; [ "$flag" = "fail-only" ] && fo="--fail-only"
  ( cd "$REPO" && CDKPF_REGION="$REGION" bash bench/verify-rule.sh "$rule" $fo ) > "$OUT/$rule.log" 2>&1
  rc=$?
  fstat=$(grep -m1 '^fail: finalStatus=' "$OUT/$rule.log" | cut -d= -f2-)
  # バックスラッシュは落とす: YAML の二重引用符スカラーで不正なエスケープになり、
  # Python の re.sub 置換文字列でも \w などが "bad escape" 例外になる（2026-09-22 実測）
  freason=$(grep -m1 '^fail: reason=' "$OUT/$rule.log" | cut -d= -f2- | tr -d '\\' | tr '\t"' "  '" | cut -c1-300)
  pstat=$(grep -m1 '^pass: finalStatus=' "$OUT/$rule.log" | cut -d= -f2-)
  printf '%s\t%s\t%s\t%s\t%s\n' "$rule" "$rc" "$fstat" "${pstat:-fail-only}" "$freason" >> "$SUMMARY"
  echo "$rule rc=$rc fail=$fstat pass=${pstat:-fail-only}"
  if [ "$rc" -eq 0 ]; then
    meta=$(find "$REPO/rules" -maxdepth 2 -type d -name "$rule")/meta.yaml
    if [ -n "$pstat" ]; then line="bench $TODAY $REGION: fail -> \\\"$freason\\\" ($fstat); pass -> $pstat"
    else line="bench $TODAY $REGION: fail -> \\\"$freason\\\" ($fstat); pass: fail-only (see #66)"; fi
    python3 - "$meta" "$line" <<'PY'
import re,sys
p,line=sys.argv[1],sys.argv[2]
s=open(p).read()
s2=re.sub(r'bench: PENDING[^"]*', lambda m: line, s, count=1)  # lambda: 置換文字列のエスケープ解釈を無効化
open(p,'w').write(s2)
print('meta patched' if s2!=s else 'WARN: PENDING marker not found', p)
PY
  fi
done < "$LIST"
echo "--- summary: $SUMMARY"; awk -F'\t' '{c[$2]++} END {for (k in c) print "rc="k": "c[k]}' "$SUMMARY"
