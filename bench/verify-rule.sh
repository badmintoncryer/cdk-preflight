#!/bin/bash
# 実機再現ゲート: ルールの fail テンプレートが実際にデプロイ失敗し、
# pass テンプレートがデプロイ成功することを AWS 実環境で確認する。
# 使い方: bash bench/verify-rule.sh <rule-id> [--fail-only]
# スタックは cdkpf-* 命名で作成し、必ず削除する。コストは失敗スタックのみで実質ゼロ。
set -u
cd "$(dirname "$0")/.."
REGION="${CDKPF_REGION:-us-east-1}"
RULE="${1:?usage: verify-rule.sh <rule-id> [--fail-only]}"
FAIL_ONLY="${2:-}"
DIR=$(find rules -maxdepth 2 -type d -name "$RULE" | head -1)
[ -z "$DIR" ] && { echo "rule not found: $RULE"; exit 1; }
mkdir -p bench/logs
LOG="bench/logs/$RULE.log"
: > "$LOG"

poll_terminal() { # stack -> echo final status
  local stack=$1
  for _ in $(seq 1 90); do
    st=$(aws cloudformation describe-stacks --stack-name "$stack" --region "$REGION" \
      --query "Stacks[0].StackStatus" --output text 2>/dev/null || echo GONE)
    case "$st" in
      CREATE_COMPLETE|CREATE_FAILED|ROLLBACK_COMPLETE|ROLLBACK_FAILED|GONE) echo "$st"; return ;;
    esac
    sleep 10
  done
  echo TIMEOUT
}

cleanup() {
  local stack=$1
  aws cloudformation delete-stack --stack-name "$stack" --region "$REGION" 2>/dev/null
  aws cloudformation wait stack-delete-complete --stack-name "$stack" --region "$REGION" 2>/dev/null
}

echo "=== $RULE: fail template ===" | tee -a "$LOG"
FSTACK="cdkpf-$RULE-fail"
aws cloudformation create-stack --stack-name "$FSTACK" --region "$REGION" \
  --template-body "file://$DIR/templates/fail.template.json" \
  --capabilities CAPABILITY_NAMED_IAM --output text >> "$LOG" 2>&1
FSTATUS=$(poll_terminal "$FSTACK")
REASON=$(aws cloudformation describe-stack-events --stack-name "$FSTACK" --region "$REGION" \
  --query "StackEvents[?ResourceStatus=='CREATE_FAILED']|[-1].ResourceStatusReason" --output text 2>/dev/null)
echo "fail: finalStatus=$FSTATUS" | tee -a "$LOG"
echo "fail: reason=$REASON" | tee -a "$LOG"
cleanup "$FSTACK"
if [ "$FSTATUS" = "CREATE_COMPLETE" ]; then
  echo "!! BROKEN-EXPECTATION: fail template deployed successfully — the constraint may have drifted" | tee -a "$LOG"
  exit 2
fi

if [ "$FAIL_ONLY" != "--fail-only" ]; then
  echo "=== $RULE: pass template ===" | tee -a "$LOG"
  PSTACK="cdkpf-$RULE-pass"
  aws cloudformation create-stack --stack-name "$PSTACK" --region "$REGION" \
    --template-body "file://$DIR/templates/pass.template.json" \
    --capabilities CAPABILITY_NAMED_IAM --output text >> "$LOG" 2>&1
  PSTATUS=$(poll_terminal "$PSTACK")
  echo "pass: finalStatus=$PSTATUS" | tee -a "$LOG"
  cleanup "$PSTACK"
  [ "$PSTATUS" != "CREATE_COMPLETE" ] && { echo "!! pass template failed to deploy — fixture is not clean" | tee -a "$LOG"; exit 3; }
fi

echo "OK: $RULE verified (fail=$FSTATUS)" | tee -a "$LOG"
