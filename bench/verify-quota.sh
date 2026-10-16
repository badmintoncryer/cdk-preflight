#!/bin/bash
# checkQuotas の実機ゲート（AGENTS.md 原則 7）。verify-rule.sh はクォータ超過を足場のノイズとして
# INCONCLUSIVE に落とすが、ここではクォータ超過こそが当てたい失敗になる。
#
# EIP（ec2/L-0263D0A3）で境界の両側を取る:
#   1. アカウントの適用値 Q と使用量 U を読み、U = Q - 1 になるまで EIP を確保して埋める
#   2. EIP を 1 個作るスタック（ちょうど Q）: checkQuotas は黙り、デプロイは CREATE_COMPLETE
#   3. EIP を 2 個作るスタック（Q + 1）: checkQuotas が pf-quota-elastic-ips-per-region で synth を止め、
#      同じテンプレートの実デプロイは上限の文面で倒れる
#   4. 確保した EIP とスタックを必ず消す
# VPC / IGW は同じ数え方と同じ比較を通る（test/quota.test.ts）。EIP を選ぶのは、上限が 5 のままの
# アカウントが多く、埋めるのに要る数が少ないから。課金は確保中の EIP だけ（1 個 $0.005/時）。
#
# 使い方: bash bench/verify-quota.sh   （先に npx projen compile で lib/ を作っておく）
# リージョン: CDKPF_REGION > us-east-1
# exit: 0=verified / 2=checkQuotas の判定が実機と食い違った / 4=INCONCLUSIVE
set -u
cd "$(dirname "$0")/.."
REGION="${CDKPF_REGION:-us-east-1}"
STACK_PASS=cdkpf-quota-eip-pass
STACK_FAIL=cdkpf-quota-eip-fail
WORK=$(mktemp -d)
mkdir -p bench/logs
LOG=bench/logs/verify-quota.log
: > "$LOG"
ALLOCATED=()

cleanup() {
  for s in "$STACK_PASS" "$STACK_FAIL"; do
    aws cloudformation delete-stack --stack-name "$s" --region "$REGION" >>"$LOG" 2>&1
    aws cloudformation wait stack-delete-complete --stack-name "$s" --region "$REGION" >>"$LOG" 2>&1 \
      || echo "LEFTOVER stack $s ($REGION)" | tee -a "$LOG"
  done
  for a in "${ALLOCATED[@]}"; do
    aws ec2 release-address --allocation-id "$a" --region "$REGION" >>"$LOG" 2>&1 \
      || echo "LEFTOVER eip $a ($REGION)" | tee -a "$LOG"
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

[ -f lib/index.js ] || { echo "lib/ がありません。npx projen compile を先に"; exit 4; }

quota=$(aws service-quotas get-service-quota --service-code ec2 --quota-code L-0263D0A3 --region "$REGION" \
  --query Quota.Value --output text 2>>"$LOG") \
  || quota=$(aws service-quotas get-aws-default-service-quota --service-code ec2 --quota-code L-0263D0A3 \
    --region "$REGION" --query Quota.Value --output text 2>>"$LOG") || { echo "quota unreadable"; exit 4; }
quota=${quota%.*}
used() { aws ec2 describe-addresses --filters Name=domain,Values=vpc --region "$REGION" --output json \
  --query 'length(Addresses)' 2>>"$LOG"; }
u=$(used) || { echo "usage unreadable"; exit 4; }
echo "quota=$quota used=$u region=$REGION" | tee -a "$LOG"
[ "$quota" -gt 20 ] && { echo "quota $quota は埋めるには大きすぎる"; exit 4; }

while [ "$u" -lt $((quota - 1)) ]; do
  a=$(aws ec2 allocate-address --domain vpc --region "$REGION" \
    --tag-specifications 'ResourceType=elastic-ip,Tags=[{Key=Name,Value=cdkpf-quota-probe}]' \
    --query AllocationId --output text 2>>"$LOG") || { echo "allocate failed"; exit 4; }
  ALLOCATED+=("$a")
  u=$((u + 1))
done
echo "filled to $u (allocated ${#ALLOCATED[@]})" | tee -a "$LOG"
sleep "${CDKPF_SETTLE:-0}"

# synth: <スタック名> <EIP 数> -> 0=通った / 1=止まった。テンプレートは $WORK/<スタック名>/ に出る
synth() {
  local out="$WORK/$1"
  ROOT="$PWD" OUT="$out" STACK="$1" N="$2" CDK_DEFAULT_REGION="$REGION" AWS_REGION="$REGION" node -e '
    const { App, Stack, BootstraplessSynthesizer, aws_ec2: ec2 } = require(process.env.ROOT + "/node_modules/aws-cdk-lib");
    const { Preflight } = require(process.env.ROOT + "/lib");
    const app = new App({ outdir: process.env.OUT, analyticsReporting: false });
    const s = new Stack(app, process.env.STACK, { synthesizer: new BootstraplessSynthesizer() });
    // 1 個ずつ作らせる。並行に作ると EC2 の上限判定をすり抜け、上限 5 で 6 個目まで通る
    // （2026-10-16 us-east-1 で 2 回再現。CLI から順に確保すると 6 個目で AddressLimitExceeded）
    let prev;
    for (let i = 0; i < Number(process.env.N); i++) {
      const eip = new ec2.CfnEIP(s, "Eip" + i, { domain: "vpc" });
      if (prev) eip.addDependency(prev);
      prev = eip;
    }
    Preflight.apply(app, { checkQuotas: true, quotaCacheTtl: require(process.env.ROOT + "/node_modules/aws-cdk-lib").Duration.seconds(0) });
    app.synth();
  ' >"$WORK/$1.synth.log" 2>&1
  local rc=$?
  cat "$WORK/$1.synth.log" >> "$LOG"
  return $rc
}

deploy() { # <スタック名> -> 終端ステータスと失敗理由を stdout
  aws cloudformation create-stack --stack-name "$1" --region "$REGION" \
    --template-body "file://$WORK/$1/$1.template.json" --on-failure ROLLBACK >>"$LOG" 2>&1 || return 1
  aws cloudformation wait stack-create-complete --stack-name "$1" --region "$REGION" >>"$LOG" 2>&1
  aws cloudformation describe-stacks --stack-name "$1" --region "$REGION" --query 'Stacks[0].StackStatus' --output text
  aws cloudformation describe-stack-events --stack-name "$1" --region "$REGION" --output text \
    --query "StackEvents[].[Timestamp,LogicalResourceId,ResourceStatus,PhysicalResourceId]" >>"$LOG" 2>&1
  aws cloudformation describe-stack-events --stack-name "$1" --region "$REGION" --output text \
    --query "StackEvents[?ResourceStatus=='CREATE_FAILED'].ResourceStatusReason" | head -1
}

verdict=0
if synth "$STACK_PASS" 1; then
  grep -q pf-quota-check-skipped "$WORK/$STACK_PASS.synth.log" && { echo "check skipped (credentials?)"; exit 4; }
  echo "pass synth: clean" | tee -a "$LOG"
else
  echo "MISMATCH pass synth failed at exactly the quota" | tee -a "$LOG"; verdict=2
fi
if synth "$STACK_FAIL" 2; then
  echo "MISMATCH fail synth passed at quota + 1" | tee -a "$LOG"; verdict=2
elif grep -q pf-quota-elastic-ips-per-region "$WORK/$STACK_FAIL.synth.log"; then
  echo "fail synth: pf-quota-elastic-ips-per-region" | tee -a "$LOG"
else
  echo "fail synth stopped for another reason (see $LOG)"; exit 4
fi
# 合成を止めたテンプレートも cdk.out には書かれている
[ -f "$WORK/$STACK_FAIL/$STACK_FAIL.template.json" ] || { echo "fail template missing"; exit 4; }

# fail を先に出す。pass が EIP を 1 個握ったままだと、fail は Q + 2 になって境界を外れる。
# fail のロールバックで EIP は戻るので、その後の pass はちょうど Q になる。
fail=$(deploy "$STACK_FAIL") || { echo "create-stack failed"; exit 4; }
echo "fail deploy: $fail" | tee -a "$LOG"
pass=$(deploy "$STACK_PASS") || { echo "create-stack failed"; exit 4; }
echo "pass deploy: $pass" | tee -a "$LOG"

case "$pass" in CREATE_COMPLETE*) ;; *) echo "MISMATCH pass deploy did not complete"; verdict=2 ;; esac
if grep -q CREATE_COMPLETE <<<"$fail"; then
  echo "MISMATCH fail deploy completed"; verdict=2
elif ! grep -qiE 'maximum number of addresses|AddressLimitExceeded' <<<"$fail"; then
  echo "fail deploy fell for another reason"; exit 4
fi
[ "$verdict" -eq 0 ] && echo "VERIFIED $(date +%F) $REGION quota=$quota: 1 EIP at the limit -> synth clean, CREATE_COMPLETE; 2 EIPs -> pf-quota-elastic-ips-per-region, deploy: $(tail -1 <<<"$fail")" | tee -a "$LOG"
exit "$verdict"
