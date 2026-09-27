#!/bin/bash
# verify-rule.sh の判定の自己チェック。aws をスタブに差し替えて実際の API は叩かない。
# ルールも一時ディレクトリに作る: 実在ルールの meta.yaml に repro.expect が入ると判定が
# 変わってしまうので、テストは自前のルールだけを見る。使い方: bash bench/verify-rule.test.sh
set -u
cd "$(dirname "$0")/.."
RULE=pf-t-plain # resourceTypes: [AWS::Batch::ComputeEnvironment]、repro.expect なし
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/rules/t/pf-t-plain" "$tmp/rules/t/pf-t-expect" "$tmp/rules/t/pf-t-vpc/templates"
cat > "$tmp/rules/t/pf-t-plain/meta.yaml" <<'YAML'
id: pf-t-plain
resourceTypes: ["AWS::Batch::ComputeEnvironment"]
repro:
  method: real-deploy
  evidence: "bench 2026-09-27 us-east-1: Compute Environment must be created in ENABLED state."
YAML
sed 's/pf-t-plain/pf-t-expect/' "$tmp/rules/t/pf-t-plain/meta.yaml" > "$tmp/rules/t/pf-t-expect/meta.yaml"
echo '  expect: "must be created in ENABLED state"' >> "$tmp/rules/t/pf-t-expect/meta.yaml"
sed 's/pf-t-plain/pf-t-vpc/' "$tmp/rules/t/pf-t-plain/meta.yaml" > "$tmp/rules/t/pf-t-vpc/meta.yaml"
# bench の既定 VPC を直書きしたフィクスチャ（読み替えの対象）と、読み替えてはいけない偽の ID
cat > "$tmp/rules/t/pf-t-vpc/templates/fail.template.json" <<'JSON'
{"Resources": {"L": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {
  "Subnets": ["subnet-2e0a500f", "subnet-ab11fde7", "subnet-7f91c820", "subnet-11111111"],
  "SecurityGroups": ["sg-7d699f61"]}},
 "T": {"Type": "AWS::ElasticLoadBalancingV2::TargetGroup", "Properties": {"VpcId": "vpc-4331593e"}}}}
JSON
cat > "$tmp/aws" <<'STUB'
#!/bin/bash
# fail スタックと pass スタックで別の答えを返す（名前で見分ける）
args="$*"
echo "$args" >> "$CDKPF_STUB_CALLS"
case "$args" in *-pass*) w=P ;; *) w=F ;; esac
eval "status=\${CDKPF_STUB_${w}STATUS:-}"
eval "reason=\${CDKPF_STUB_${w}REASON:-}"
eval "sreason=\${CDKPF_STUB_${w}STACKREASON:-None}"
eval "ftype=\${CDKPF_STUB_${w}TYPE:-None}"
eval "cerr=\${CDKPF_STUB_${w}CREATE_ERR:-}"
eval "derr=\${CDKPF_STUB_${w}DESCRIBE_ERR:-}"
eval "dfails=\${CDKPF_STUB_${w}DESCRIBE_FAILS:-0}"
eval "dfrom=\${CDKPF_STUB_${w}DESCRIBE_FROM:-1}"
eval "eerr=\${CDKPF_STUB_${w}EVENTS_ERR:-}"
eval "wfail=\${CDKPF_STUB_${w}WAIT_FAIL:-}"
eval "pages=\${CDKPF_STUB_${w}PAGES:-1}"
case "$args" in
  *"describe-stacks"*"StackStatus"*)
    n=$(cat "$CDKPF_STUB_CALLS.$w" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$CDKPF_STUB_CALLS.$w"
    [ -n "$derr" ] && [ "$n" -ge "$dfrom" ] && [ "$n" -le "$dfails" ] && { echo "$derr" >&2; exit 255; }
    echo "${status:-ROLLBACK_COMPLETE}" ;;
  *"describe-stack-events"*)
    [ -z "$eerr" ] || { echo "$eerr" >&2; exit 255; }
    # クエリで答えを変える。スタブは JMESPath を評価しないので、フィルタが外すはずの文面
    # （巻き添えの取り消しなど）を返させると、ハーネス側の最後の砦だけが試される
    case "$args" in
      *ROLLBACK_IN_PROGRESS*) ans=$sreason ;; # スタック自身のロールバック開始の行
      *"LogicalResourceId=="*) ans=None ;;    # スタック自身の CREATE_FAILED
      *".ResourceType"*) ans=$ftype ;;
      *) ans=$reason ;;                       # リソースの CREATE_FAILED
    esac
    # 本物の CLI は --output text だとページ（100 件）ごとにクエリを当て、答えをページの数だけ
    # 返す。json は全ページをまとめてから当てる
    case "$args" in
      *"--output json"*) if [ "$ans" = None ]; then echo null; else printf '%s' "$ans" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; fi ;;
      *) echo "$ans"; i=1; while [ "$i" -lt "$pages" ]; do echo None; i=$((i + 1)); done ;;
    esac ;;
  *"describe-stack-resources"*) echo "" ;;
  *"wait"*"stack-delete-complete"*) [ -z "$wfail" ] || exit 255 ;;
  *"create-stack"*)
    tb=${args#*file://}; cp "${tb%% *}" "$CDKPF_STUB_CALLS.tpl" 2>/dev/null # 実際に作ろうとしたテンプレート
    [ -z "$cerr" ] || { echo "$cerr" >&2; exit 254; } ;;
  # 別アカウントの既定 VPC。サブネットは AZ ID で答える
  *"describe-vpcs"*) echo "${CDKPF_STUB_VPC-vpc-0aaa}" ;;
  *"describe-security-groups"*) echo sg-0bbb ;;
  *"describe-subnets"*use1-az2*) echo subnet-0a2 ;;
  *"describe-subnets"*use1-az4*) echo subnet-0a4 ;;
  *"describe-subnets"*use1-az6*) echo subnet-0a6 ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$tmp/aws"
printf '#!/bin/bash\nexit 0\n' > "$tmp/sleep"   # バックオフを実時間で待たない
chmod +x "$tmp/sleep"
export PATH="$tmp:$PATH" CDKPF_STUB_CALLS="$tmp/calls"

run() { # run <failed type> <reason> [--fail-only 以外を渡すと pass 側も回す] -> exit code
  rm -f "$tmp/calls" "$tmp/calls.F" "$tmp/calls.P" "$tmp/calls.tpl"; : > "$tmp/calls"
  # 予算は保険。リトライの打ち切りが壊れたら 1 時間ではなく 1 分で落ちるように
  CDKPF_STUB_FTYPE="$1" CDKPF_STUB_FREASON="$2" CDKPF_RULES_DIR="$tmp/rules" CDKPF_REGION=us-east-1 CDKPF_POLL_BUDGET=60 \
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

# CloudFormation は同じことを空白なしの HandlerErrorCode: AlreadyExists でも言う。"already exists"
# だけを見ていると足場の衝突が素通りして verified になる（2026-09-22、pf-servicediscovery-* で
# 足場の HttpNamespace が前回の消し残りとぶつかったのに OK が出た）。
COLLIDE='Resource handler returned message: "Another operation of type CreateHttpNamespace and id abc has completed (Service: ServiceDiscovery, Status Code: 400, Request ID: r1)" (RequestToken: t1, HandlerErrorCode: AlreadyExists)'
got=$(run "AWS::ServiceDiscovery::HttpNamespace" "$COLLIDE")
expect 4 "$got" "AlreadyExists without a space is still a scaffolding collision"
grep -q "INCONCLUSIVE: the fixture's AWS::ServiceDiscovery::HttpNamespace failed" "$tmp/out" \
  || { echo "FAIL: the no-space AlreadyExists collision was not named"; cat "$tmp/out"; exit 1; }
grep -q "^OK:" "$tmp/out" \
  && { echo "FAIL: a scaffolding collision was written up as verified"; cat "$tmp/out"; exit 1; }

# 見分けているのは文面ではなく $ftype。同じ文面でもルールの対象型が倒れたなら本物の証拠
got=$(run "AWS::Batch::ComputeEnvironment" "$COLLIDE")
expect 0 "$got" "AlreadyExists on the rule's own type is evidence, not scaffolding"

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

# pass が本当にデプロイされて CREATE_COMPLETE 以外で終わったなら exit 3 のまま（下の 4 と別物）
got=$(run "AWS::Batch::ComputeEnvironment" "Compute Environment must be created in ENABLED state." "")
expect 3 "$got" "a pass stack that deployed and rolled back is an unclean fixture, not INCONCLUSIVE"

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

# describe-stacks の非ゼロ終了を一律 GONE に潰すと、進行中のスタックを消しにかかる
# （2026-09-22、4 並列で pf-servicediscovery-* の 2 本）。GONE と言えるのは
# ValidationError が「無い」と名指ししたときだけ。
GONE_ERR="An error occurred (ValidationError) when calling the DescribeStacks operation: Stack with id cdkpf-x does not exist"
THROTTLE="An error occurred (Throttling) when calling the DescribeStacks operation (reached max retries: 4): Rate exceeded"

# 本当に消えている: GONE のままでなければならない（並走する sweep が消すことは実際にある）
got=$(CDKPF_STUB_FDESCRIBE_ERR="$GONE_ERR" CDKPF_STUB_FDESCRIBE_FAILS=99 run "None" "")
expect 4 "$got" "a stack the API says does not exist is still GONE"
grep -q "ended GONE" "$tmp/out" \
  || { echo "FAIL: a genuinely missing stack must still report GONE"; cat "$tmp/out"; exit 1; }
grep -q "delete-stack" "$tmp/calls" \
  && { echo "FAIL: cleanup deleted a stack the API already said is gone"; exit 1; }

# 一過性のスロットリング: 数回リトライして読めれば、判定は普通に続く
got=$(CDKPF_STUB_FDESCRIBE_ERR="$THROTTLE" CDKPF_STUB_FDESCRIBE_FAILS=2 \
      run "AWS::Batch::ComputeEnvironment" "Compute Environment must be created in ENABLED state.")
expect 0 "$got" "throttling on the way to a terminal status must be retried, not read as GONE"
grep -qE "GONE|INCONCLUSIVE" "$tmp/out" \
  && { echo "FAIL: a transient read error leaked into the verdict"; cat "$tmp/out"; exit 1; }

# 最後まで読めなかった: GONE とは別の理由で INCONCLUSIVE。スタックは消しにいく
got=$(CDKPF_STUB_FDESCRIBE_ERR="$THROTTLE" CDKPF_STUB_FDESCRIBE_FAILS=99 run "None" "")
expect 4 "$got" "a status that never becomes readable is INCONCLUSIVE"
grep -q "could not read the fail stack" "$tmp/out" \
  || { echo "FAIL: an unreadable status was not reported as such"; cat "$tmp/out"; exit 1; }
grep -q "GONE" "$tmp/out" \
  && { echo "FAIL: an unreadable status was reported as GONE"; cat "$tmp/out"; exit 1; }
grep -q "delete-stack" "$tmp/calls" \
  || { echo "FAIL: cleanup skipped the delete because it could not read the status"; exit 1; }

# pass 側も同じ: 読めなかっただけで「フィクスチャが汚い」(exit 3) にしない
got=$(CDKPF_STUB_PDESCRIBE_ERR="$THROTTLE" CDKPF_STUB_PDESCRIBE_FAILS=99 \
      run "AWS::Batch::ComputeEnvironment" "Compute Environment must be created in ENABLED state." "")
expect 4 "$got" "an unreadable pass stack is INCONCLUSIVE, not an unclean fixture"
grep -q "could not read the pass stack" "$tmp/out" \
  || { echo "FAIL: the pass-side unreadable status was not reported"; cat "$tmp/out"; exit 1; }
! grep -q "fixture is not clean" "$tmp/out" \
  || { echo "FAIL: an unreadable pass stack must not read as an unclean fixture"; cat "$tmp/out"; exit 1; }

# 一番高くつく取り違え: イベントが読めないと足場ガードが無言で no-op になり、足場が
# 倒れただけのロールバックが verified として meta.yaml に焼き付く
got=$(CDKPF_STUB_FEVENTS_ERR="$THROTTLE" run "AWS::EC2::VPC" "The maximum number of VPCs has been reached.")
expect 4 "$got" "an unreadable failure reason must not verify — the scaffolding guard cannot run"
grep -q "could not read the fail stack's events" "$tmp/out" \
  || { echo "FAIL: an unreadable event log was not reported"; cat "$tmp/out"; exit 1; }
grep -q "^OK:" "$tmp/out" \
  && { echo "FAIL: a rule was verified without ever reading why the stack fell over"; cat "$tmp/out"; exit 1; }

# ただし fail が丸ごと通ったことは describe-stacks だけで分かる。BROKEN を降格させない
got=$(CDKPF_STUB_FSTATUS=CREATE_COMPLETE CDKPF_STUB_FEVENTS_ERR="$THROTTLE" run "None" "")
expect 2 "$got" "BROKEN-EXPECTATION must not be downgraded by an unrelated read error"

# pass 側: 読めなかっただけで「フィクスチャが汚い」(exit 3) と断じない
got=$(CDKPF_STUB_PEVENTS_ERR="$THROTTLE" \
      run "AWS::Batch::ComputeEnvironment" "Compute Environment must be created in ENABLED state." "")
expect 4 "$got" "an unreadable pass-side event log is INCONCLUSIVE, not an unclean fixture"
! grep -q "fixture is not clean" "$tmp/out" \
  || { echo "FAIL: a read error was blamed on the fixture"; cat "$tmp/out"; exit 1; }

# LEFTOVER は消し残りの索引として読むもの。wait が落ちても消えているなら載せない
# （cleanup の 3 回目の describe から「存在しない」を返す: 1=poll, 2=cleanup 入口, 3=wait 後）
got=$(CDKPF_STUB_FWAIT_FAIL=1 CDKPF_STUB_FDESCRIBE_ERR="$GONE_ERR" \
      CDKPF_STUB_FDESCRIBE_FROM=3 CDKPF_STUB_FDESCRIBE_FAILS=99 \
      run "AWS::Batch::ComputeEnvironment" "Compute Environment must be created in ENABLED state.")
expect 0 "$got" "a failed wait on an already-deleted stack still verifies"
grep -q "LEFTOVER" "$tmp/out" \
  && { echo "FAIL: a stack that is actually gone was logged as a leftover"; cat "$tmp/out"; exit 1; }

# --- 倒れた理由が制約を名指ししているか（#264）---
# 倒れたことだけでは証拠にならない。理由が読めない、または巻き添えの文しか無いのに OK を
# 出していた（2026-09-25 の cloudformation の月次で 21 本中 5 本）。
got=$(run "None" "")
expect 4 "$got" "a fallen stack with no readable reason must not verify"
grep -q "no reason on the fail stack" "$tmp/out" \
  || { echo "FAIL: a missing reason was not reported as such"; cat "$tmp/out"; exit 1; }

# 入れ子スタックの本物の失敗を読み飛ばし、隣の巻き添えの取り消しを理由として拾っていた
got=$(run "AWS::SNS::Topic" "Resource creation cancelled")
expect 4 "$got" "a collateral cancellation is not evidence"

# リソースに紐づかない失敗（Outputs の Export など）は、既定のロールバックだとスタック自身の
# ロールバック開始の行にしか理由が載らない
EXPORT_MAX="Cannot export output A with length 1025. Max length of 1024 exceeded.. Rollback requested by user."
got=$(CDKPF_STUB_FSTACKREASON="$EXPORT_MAX" run "None" "")
expect 0 "$got" "a stack-level failure verifies on the reason from the rollback event"
grep -qF "fail: reason=$EXPORT_MAX" "$tmp/out" \
  || { echo "FAIL: the stack-level reason was not read"; cat "$tmp/out"; exit 1; }

# 同じ行でも、リソースの失敗を並べ直しただけのまとめ文は証拠ではない
got=$(CDKPF_STUB_FSTACKREASON="The following resource(s) failed to create: [S, Pad]. Rollback requested by user." run "None" "")
expect 4 "$got" "the rollback summary line is not evidence"

# イベントが 100 件を超えるスタック: --output text はページごとにクエリを当てるので、どのページにも
# 理由が無いと "None" がページの数だけ並び、1 つの "None" と見分けられずに OK になっていた
got=$(CDKPF_STUB_FPAGES=2 run "None" "None")
expect 4 "$got" "a stack whose events span two pages with no reason on either must not verify"

# repro.expect があれば、理由がそれを逐語で含むときだけ verified
got=$(RULE=pf-t-expect run "AWS::Batch::ComputeEnvironment" "Compute Environment must be created in ENABLED state.")
expect 0 "$got" "a reason that contains repro.expect verifies"
got=$(RULE=pf-t-expect run "AWS::Batch::ComputeEnvironment" "Role arn:aws:iam::111111111111:role/cdkpf-probe does not exist")
expect 4 "$got" "falling over on the rule's own type for another reason is not evidence"
grep -q "fell for a different reason than repro.expect" "$tmp/out" \
  || { echo "FAIL: the mismatch was not reported as such"; cat "$tmp/out"; exit 1; }

# create-stack の同期拒否: 足場が倒れる余地が無いぶん一番強い証拠だが、スロットルや認証切れと
# 見分けられるのは repro.expect を名指ししたときだけ
SYNC="An error occurred (ValidationError) when calling the CreateStack operation: Compute Environment must be created in ENABLED state."
got=$(RULE=pf-t-expect CDKPF_STUB_FCREATE_ERR="$SYNC" run "None" "")
expect 0 "$got" "a synchronous rejection that names repro.expect verifies"
grep -qF "fail: reason=$SYNC" "$tmp/out" \
  || { echo "FAIL: the synchronous rejection was not written up as the reason"; cat "$tmp/out"; exit 1; }
got=$(RULE=pf-t-expect CDKPF_STUB_FCREATE_ERR="$APIERR" run "None" "")
expect 4 "$got" "a synchronous rejection that does not name repro.expect stays INCONCLUSIVE"
# fail を同期拒否で確かめたあとも pass 側は普通に回る
got=$(RULE=pf-t-expect CDKPF_STUB_FCREATE_ERR="$SYNC" CDKPF_STUB_PSTATUS=CREATE_COMPLETE run "None" "" "")
expect 0 "$got" "a synchronously rejected fail template still runs the pass side"
# pass 側の同期拒否は、期待文を含んでいてもフィクスチャが通らなかったことに変わりない
got=$(RULE=pf-t-expect CDKPF_STUB_PCREATE_ERR="$SYNC" \
      run "AWS::Batch::ComputeEnvironment" "Compute Environment must be created in ENABLED state." "")
expect 4 "$got" "a synchronous rejection of the pass template is never evidence"

# --- bench の既定 VPC の ID は、作る直前に自アカウントの既定 VPC へ読み替える ---
# 月次アカウントには bench のサブネットが無く、制約より先に InvalidSubnetID.NotFound で倒れていた
got=$(RULE=pf-t-vpc run "AWS::Batch::ComputeEnvironment" "Compute Environment must be created in ENABLED state.")
expect 0 "$got" "a fixture on bench's default VPC still runs in another account"
for id in vpc-0aaa sg-0bbb subnet-0a2 subnet-0a4 subnet-0a6 subnet-11111111; do
  grep -q "\"$id\"" "$tmp/calls.tpl" || { echo "FAIL: $id missing from the deployed template"; cat "$tmp/calls.tpl"; exit 1; }
done
grep -qE 'vpc-4331593e|sg-7d699f61|subnet-(2e0a500f|ab11fde7|7f91c820)' "$tmp/calls.tpl" \
  && { echo "FAIL: a bench default-VPC ID survived into the deployed template"; cat "$tmp/calls.tpl"; exit 1; }
# AZ 名ではなく AZ ID で合わせる（AZ 名と物理 AZ の対応はアカウントごとに違う）
tr -d ' \n' < "$tmp/calls.tpl" | grep -q '"Subnets":\["subnet-0a2","subnet-0a4","subnet-0a6","subnet-11111111"\]' \
  || { echo "FAIL: the subnets were not matched by AZ ID"; cat "$tmp/calls.tpl"; exit 1; }

# 既定 VPC が無いアカウントでは、別の NotFound で倒して「検証した」と読ませず、作る前に降りる
got=$(RULE=pf-t-vpc CDKPF_STUB_VPC=None run "AWS::Batch::ComputeEnvironment" "Compute Environment must be created in ENABLED state.")
expect 4 "$got" "no default VPC to stand in for bench's is INCONCLUSIVE"
grep -q "has no default VPC" "$tmp/out" || { echo "FAIL: the missing default VPC was not named"; cat "$tmp/out"; exit 1; }
grep -q "create-stack" "$tmp/calls" && { echo "FAIL: created a stack without a default VPC to point at"; exit 1; }

# 直書きの無いテンプレートには EC2 を引きに行かない
got=$(run "AWS::Batch::ComputeEnvironment" "Compute Environment must be created in ENABLED state.")
grep -q "describe-vpcs" "$tmp/calls" && { echo "FAIL: looked up a default VPC for a template that names none"; exit 1; }

echo "ok: verify-rule.sh default-VPC localization + scaffolding guard + create-stack rejection + unreadable status/events + leftover noise + reason must name the constraint"
