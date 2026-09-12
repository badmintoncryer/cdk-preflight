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
RTYPES=$(grep -E '^resourceTypes:' "$DIR/meta.yaml")
REGION="${CDKPF_REGION:-${META_REGION:-ap-northeast-1}}"
mkdir -p bench/logs
LOG="bench/logs/$RULE.log"
: > "$LOG"

poll_terminal() { # stack -> echo final status
  local stack=$1
  # 30 分。ElastiCache / MemoryDB のクラスタは作成にも削除にも 10-25 分かかるので、
  # 15 分では pass テンプレートが TIMEOUT=INCONCLUSIVE になる（2026-09-06 実測）。
  for _ in $(seq 1 180); do
    st=$(aws cloudformation describe-stacks --stack-name "$stack" --region "$REGION" \
      --query "Stacks[0].StackStatus" --output text 2>/dev/null || echo GONE)
    case "$st" in
      CREATE_COMPLETE|CREATE_FAILED|ROLLBACK_COMPLETE|ROLLBACK_FAILED|GONE) echo "$st"; return ;;
    esac
    sleep 10
  done
  echo TIMEOUT
}

reason_of() { # リソースの CREATE_FAILED を優先。無ければスタックレベル（早期検証の失敗はこちらにしか出ない）
  local q r
  for q in "ResourceStatus=='CREATE_FAILED' && ResourceType!='AWS::CloudFormation::Stack'" "ResourceStatus=='CREATE_FAILED'"; do
    r=$(aws cloudformation describe-stack-events --stack-name "$1" --region "$REGION" \
      --query "StackEvents[?$q]|[-1].ResourceStatusReason" --output text 2>/dev/null)
    [ -n "$r" ] && [ "$r" != "None" ] && { echo "$r"; return; }
  done
  echo "$r"
}

failed_type() { # スタックの中で最初に CREATE_FAILED になったリソースの型
  aws cloudformation describe-stack-events --stack-name "$1" --region "$REGION" \
    --query "StackEvents[?ResourceStatus=='CREATE_FAILED' && ResourceType!='AWS::CloudFormation::Stack']|[-1].ResourceType" \
    --output text 2>/dev/null
}

# フィクスチャは検査対象の周りに足場（VPC、ロール、バケット）を建てる。足場のほうが
# 倒れた場合 — アカウントのクォータ、前回の消し残り、スロットリング — でもスタックは
# ROLLBACK_COMPLETE で終わるので、そのままだと「制約を再現した」と読めてしまい、
# 嘘の証拠が meta.yaml に焼き付く（2026-09-12、VPC のクォータで計算環境のルール 6 本が
# verified に見えた）。判定するのは「倒れたのがルールの対象型」か「上限系の文面ではない」
# ときだけにする。メッセージだけで見分けようとすると誤検出する: 名前の一意性を見る
# ルールは "already exists" が、ロールのアカウントを見るルールは "is not authorized" が
# 本物の証拠になる。
scaffolding_failure() { # <失敗したリソース型> <理由> -> 足場の失敗なら 0
  local ftype=$1 reason=$2
  case "$ftype" in "" | None) return 1 ;; esac
  grep -qF "$ftype" <<<"$RTYPES" && return 1
  grep -qiE 'maximum number of|LimitExceeded|limit exceeded|quota|Rate exceeded|Throttl|already exists' <<<"$reason"
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
  --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND --output text >> "$LOG" 2>&1; then
  # ponytail: API レベルの拒否は throttle/認証エラーと本物の制約発火を区別できないので
  # 一律 INCONCLUSIVE。毎月これに落ち続けるルールが出たら期待エラー文の白判定を個別に足す
  APIERR=$(grep -iE 'error|denied|exception' "$LOG" | tail -1)
  echo "!! INCONCLUSIVE: create-stack API error: $APIERR" | tee -a "$LOG"
  cleanup "$FSTACK"
  exit 4
fi
FSTATUS=$(poll_terminal "$FSTACK")
REASON=$(reason_of "$FSTACK")
FTYPE=$(failed_type "$FSTACK")
echo "fail: finalStatus=$FSTATUS" | tee -a "$LOG"
echo "fail: reason=$REASON" | tee -a "$LOG"
cleanup "$FSTACK"
if scaffolding_failure "$FTYPE" "$REASON"; then
  echo "!! INCONCLUSIVE: the fixture's $FTYPE failed before the constraint could fire: $REASON" | tee -a "$LOG"
  exit 4
fi
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
      --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND --output text >> "$LOG" 2>&1
  PSTATUS=$(poll_terminal "$PSTACK")
  PREASON=$(reason_of "$PSTACK")
  PTYPE=$(failed_type "$PSTACK")
  echo "pass: finalStatus=$PSTATUS" | tee -a "$LOG"
  echo "pass: reason=$PREASON" | tee -a "$LOG"
  cleanup "$PSTACK"
  if scaffolding_failure "$PTYPE" "$PREASON"; then
    echo "!! INCONCLUSIVE: the pass fixture's $PTYPE failed for a reason of its own: $PREASON" | tee -a "$LOG"
    exit 4
  fi
  [ "$PSTATUS" != "CREATE_COMPLETE" ] && { echo "!! pass template failed to deploy — fixture is not clean" | tee -a "$LOG"; exit 3; }
fi

echo "OK: $RULE verified (fail=$FSTATUS)" | tee -a "$LOG"
