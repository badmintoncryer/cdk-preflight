#!/bin/bash
# 実機再現ゲート: ルールの fail テンプレートが実際にデプロイ失敗し、
# pass テンプレートがデプロイ成功することを AWS 実環境で確認する。
# 使い方: bash bench/verify-rule.sh <rule-id> [--fail-only]
# リージョン: CDKPF_REGION > meta.yaml の benchRegion > ap-northeast-1
# exit: 0=verified / 2=BROKEN(fail が通った=制約ドリフト疑い) / 3=pass 不成立 / 4=INCONCLUSIVE(判定不能)
# スタックは cdkpf-* 命名で作成し、必ず削除する。コストは失敗スタックのみで実質ゼロ。
set -u
cd "$(dirname "$0")/.."
RULE="${1:?usage: verify-rule.sh <rule-id> [--fail-only]}"
FAIL_ONLY="${2:-}"
DIR=$(find rules -maxdepth 2 -type d -name "$RULE" | head -1)
[ -z "$DIR" ] && { echo "rule not found: $RULE"; exit 1; }
META_REGION=$(grep -E '^benchRegion:' "$DIR/meta.yaml" | awk '{print $2}')
REGION="${CDKPF_REGION:-${META_REGION:-ap-northeast-1}}"
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

cleanup() { # 無人運用前提: DELETE_FAILED で固着したら retain 削除まで自動で撃つ
  local stack=$1
  aws cloudformation describe-stacks --stack-name "$stack" --region "$REGION" >/dev/null 2>&1 || return 0
  aws cloudformation delete-stack --stack-name "$stack" --region "$REGION" 2>/dev/null
  aws cloudformation wait stack-delete-complete --stack-name "$stack" --region "$REGION" 2>/dev/null && return 0
  local ids
  ids=$(aws cloudformation describe-stack-resources --stack-name "$stack" --region "$REGION" \
    --query "StackResources[?ResourceStatus=='DELETE_FAILED'].LogicalResourceId" --output text 2>/dev/null)
  if [ -z "$ids" ] || [ "$ids" = "None" ]; then
    echo "LEFTOVER: $stack ($REGION) delete did not complete" | tee -a "$LOG"
    return 0
  fi
  aws cloudformation delete-stack --stack-name "$stack" --region "$REGION" --retain-resources $ids 2>/dev/null
  if aws cloudformation wait stack-delete-complete --stack-name "$stack" --region "$REGION" 2>/dev/null; then
    echo "LEFTOVER: $stack ($REGION) deleted with retained resources: $ids" | tee -a "$LOG"
  else
    echo "LEFTOVER: $stack ($REGION) still stuck after retain-delete: $ids" | tee -a "$LOG"
  fi
}

echo "=== $RULE: fail template ($REGION) ===" | tee -a "$LOG"
FSTACK="cdkpf-$RULE-fail"
if ! aws cloudformation create-stack --stack-name "$FSTACK" --region "$REGION" \
  --template-body "file://$DIR/templates/fail.template.json" \
  --tags Key=cdkpf,Value="$RULE" \
  --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND --output text >> "$LOG" 2>&1; then
  # ponytail: API レベルの拒否は throttle/認証エラーと本物の制約発火を区別できないので
  # 一律 INCONCLUSIVE。毎月これに落ち続けるルールが出たら期待エラー文の白判定を個別に足す
  APIERR=$(grep -iE 'error|denied|exception' "$LOG" | tail -1)
  echo "!! INCONCLUSIVE: create-stack API error: $APIERR" | tee -a "$LOG"
  cleanup "$FSTACK"
  exit 4
fi
FSTATUS=$(poll_terminal "$FSTACK")
REASON=$(aws cloudformation describe-stack-events --stack-name "$FSTACK" --region "$REGION" \
  --query "StackEvents[?ResourceStatus=='CREATE_FAILED']|[-1].ResourceStatusReason" --output text 2>/dev/null)
echo "fail: finalStatus=$FSTATUS" | tee -a "$LOG"
echo "fail: reason=$REASON" | tee -a "$LOG"
cleanup "$FSTACK"
case "$FSTATUS" in
  CREATE_COMPLETE)
    echo "!! BROKEN-EXPECTATION: fail template deployed successfully — the constraint may have drifted" | tee -a "$LOG"
    exit 2 ;;
  GONE|TIMEOUT)
    echo "!! INCONCLUSIVE: fail stack ended $FSTATUS — cannot judge the constraint" | tee -a "$LOG"
    exit 4 ;;
esac

if [ "$FAIL_ONLY" != "--fail-only" ]; then
  echo "=== $RULE: pass template ($REGION) ===" | tee -a "$LOG"
  PSTACK="cdkpf-$RULE-pass"
  aws cloudformation create-stack --stack-name "$PSTACK" --region "$REGION" \
    --template-body "file://$DIR/templates/pass.template.json" \
    --tags Key=cdkpf,Value="$RULE" \
    --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND --output text >> "$LOG" 2>&1
  PSTATUS=$(poll_terminal "$PSTACK")
  echo "pass: finalStatus=$PSTATUS" | tee -a "$LOG"
  cleanup "$PSTACK"
  [ "$PSTATUS" != "CREATE_COMPLETE" ] && { echo "!! pass template failed to deploy — fixture is not clean" | tee -a "$LOG"; exit 3; }
fi

echo "OK: $RULE verified (fail=$FSTATUS)" | tee -a "$LOG"
