#!/bin/bash
# 月次オーケストレータ: 1 サービスの全ルールを fail-only で実機検証し、
# 結果を bench/out/<service>.jsonl に 1 ルール 1 行で集計する。
# 使い方: bash bench/verify-all.sh <service>
# exit: 0=全 OK / 2=BROKEN あり（制約ドリフト疑い） / 4=INCONCLUSIVE のみ
set -u
cd "$(dirname "$0")/.."
SVC="${1:?usage: verify-all.sh <service>}"
[ -d "rules/$SVC" ] || { echo "service not found: $SVC"; exit 1; }
mkdir -p bench/out
OUT="bench/out/$SVC.jsonl"
: > "$OUT"

emit() { # rule status region detail
  python3 -c 'import json,sys; print(json.dumps({"rule":sys.argv[1],"service":sys.argv[2],"status":sys.argv[3],"region":sys.argv[4],"detail":sys.argv[5]}))' \
    "$1" "$SVC" "$2" "$3" "$4" >> "$OUT"
}

overall=0
for d in rules/"$SVC"/*/; do
  rule=$(basename "$d")
  method=$(grep -E '^\s*method:' "$d/meta.yaml" | awk '{print $2}')
  case "$method" in
    real-deploy|research-case) ;;
    *) emit "$rule" SKIPPED - "repro.method=$method"; continue ;;
  esac
  region=$(grep -E '^benchRegion:' "$d/meta.yaml" | awk '{print $2}')
  region="${region:-ap-northeast-1}"

  CDKPF_REGION="$region" bash bench/verify-rule.sh "$rule" --fail-only
  rc=$?
  if [ "$rc" -eq 4 ]; then # 判定不能は 1 回だけリトライ（throttle 等の一過性を吸収）
    echo "retrying $rule after INCONCLUSIVE"
    CDKPF_REGION="$region" bash bench/verify-rule.sh "$rule" --fail-only
    rc=$?
  fi

  detail=$(grep -E '^(fail: reason=|!!|LEFTOVER:)' "bench/logs/$rule.log" | tail -3 | tr '\n' ' ')
  case "$rc" in
    0) emit "$rule" OK "$region" "$detail" ;;
    2) emit "$rule" BROKEN "$region" "$detail"; overall=2 ;;
    *) emit "$rule" INCONCLUSIVE "$region" "$detail"; [ "$overall" -eq 0 ] && overall=4 ;;
  esac
done

echo "=== $SVC summary ==="
cat "$OUT"
exit "$overall"
