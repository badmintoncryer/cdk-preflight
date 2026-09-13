#!/bin/bash
# verify-rule.sh の「足場が倒れただけ」判定の自己チェック。aws をスタブに差し替えて
# 実際の API は叩かない。使い方: bash bench/verify-rule.test.sh
set -u
cd "$(dirname "$0")/.."
RULE=pf-batch-ce-state-enabled # resourceTypes: [AWS::Batch::ComputeEnvironment]
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/aws" <<'STUB'
#!/bin/bash
# fail スタックと pass スタックで別の答えを返す（名前で見分ける）
args="$*"
case "$args" in *-pass*) w=P ;; *) w=F ;; esac
eval "status=\${CDKPF_STUB_${w}STATUS:-}"
eval "reason=\${CDKPF_STUB_${w}REASON:-}"
eval "ftype=\${CDKPF_STUB_${w}TYPE:-None}"
eval "cerr=\${CDKPF_STUB_${w}CREATE_ERR:-}"
case "$args" in
  *"describe-stacks"*"StackStatus"*) echo "${status:-ROLLBACK_COMPLETE}" ;;
  *"describe-stack-events"*ResourceStatusReason*) echo "$reason" ;;
  *"describe-stack-events"*ResourceType*) echo "$ftype" ;;
  *"describe-stack-resources"*) echo "" ;;
  *"create-stack"*) [ -z "$cerr" ] || { echo "$cerr" >&2; exit 254; } ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$tmp/aws"
export PATH="$tmp:$PATH"

run() { # run <failed type> <reason> [--fail-only 以外を渡すと pass 側も回す] -> exit code
  CDKPF_STUB_FTYPE="$1" CDKPF_STUB_FREASON="$2" CDKPF_REGION=us-east-1 \
    bash bench/verify-rule.sh "$RULE" "${3---fail-only}" > "$tmp/out" 2>&1
  echo $?
}
expect() { # expect <code> <got> <what>
  [ "$1" = "$2" ] && return 0
  echo "FAIL: $3 — expected exit $1, got $2"; cat "$tmp/out"; exit 1
}

# 足場（VPC）がアカウントのクォータで倒れた: 制約は一度も評価されていない
got=$(run "AWS::EC2::VPC" "The maximum number of VPCs has been reached.")
expect 4 "$got" "an account quota on scaffolding must not read as a reproduction"
grep -q "INCONCLUSIVE: the fixture's AWS::EC2::VPC failed" "$tmp/out" \
  || { echo "FAIL: the scaffolding message did not name the resource"; cat "$tmp/out"; exit 1; }

# 本物の制約: 倒れたのはルールの対象型
got=$(run "AWS::Batch::ComputeEnvironment" "Compute Environment must be created in ENABLED state.")
expect 0 "$got" "a constraint on the rule's own resource type must verify"

# 名前の一意性を見るルールは "already exists" が本物の証拠になる。文面だけで弾かない
got=$(run "AWS::Batch::ComputeEnvironment" "Object already exists: cdkpf-probe")
expect 0 "$got" "already exists on the rule's own type is evidence, not scaffolding"

# 足場の型でも、上限系でない文面なら判定を続ける（リソース型だけで弾かない）
got=$(run "AWS::EC2::Subnet" "The CIDR '10.0.0.0/24' conflicts with another subnet")
expect 0 "$got" "a non-quota failure elsewhere must not be swallowed"

# pass 側も同じ: fail は本物の制約で倒れ、pass は足場のクォータで倒れたケース
got=$(CDKPF_STUB_PTYPE="AWS::EC2::VPC" \
      CDKPF_STUB_PREASON="The maximum number of VPCs has been reached." \
      run "AWS::Batch::ComputeEnvironment" "Compute Environment must be created in ENABLED state." "")
expect 4 "$got" "a quota failure on the pass stack must not read as an unclean fixture"
grep -q "INCONCLUSIVE: the pass fixture's AWS::EC2::VPC" "$tmp/out" \
  || { echo "FAIL: the pass-side message did not name the resource"; cat "$tmp/out"; exit 1; }

# pass が本当にきれいなら verified
got=$(CDKPF_STUB_PSTATUS=CREATE_COMPLETE \
      run "AWS::Batch::ComputeEnvironment" "Compute Environment must be created in ENABLED state." "")
expect 0 "$got" "a clean pass stack still verifies"

# pass テンプレートが API に弾かれた場合: スタックは一度も作られないので poll は GONE を返す。
# それを「デプロイしたが CREATE_COMPLETE で終わらなかった」(exit 3) と同じ扱いにすると、
# 本当の理由（ここでは templateBody の 51200 バイト上限）がログを開くまで見えない。
APIERR="An error occurred (ValidationError) when calling the CreateStack operation: 1 validation error detected: Value '{...}' at 'templateBody' failed to satisfy constraint: Member must have length less than or equal to 51200"
got=$(CDKPF_STUB_PCREATE_ERR="$APIERR" \
      run "AWS::Batch::ComputeEnvironment" "Compute Environment must be created in ENABLED state." "")
expect 4 "$got" "a pass template the API rejects outright is INCONCLUSIVE, not an unclean fixture"
grep -q "INCONCLUSIVE: pass create-stack API error:.*51200" "$tmp/out" \
  || { echo "FAIL: the pass-side API error was not reported"; cat "$tmp/out"; exit 1; }
! grep -q "fixture is not clean" "$tmp/out" \
  || { echo "FAIL: a rejected pass template must not read as an unclean fixture"; cat "$tmp/out"; exit 1; }

# fail 側も同じ経路を通る
got=$(CDKPF_STUB_FCREATE_ERR="$APIERR" run "AWS::Batch::ComputeEnvironment" "irrelevant")
expect 4 "$got" "a fail template the API rejects outright is INCONCLUSIVE"
grep -q "INCONCLUSIVE: fail create-stack API error:.*51200" "$tmp/out" \
  || { echo "FAIL: the fail-side API error was not reported"; cat "$tmp/out"; exit 1; }

echo "ok: verify-rule.sh scaffolding guard + create-stack rejection"
