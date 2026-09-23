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
echo "$args" >> "$CDKPF_STUB_CALLS"
case "$args" in *-pass*) w=P ;; *) w=F ;; esac
eval "status=\${CDKPF_STUB_${w}STATUS:-}"
eval "reason=\${CDKPF_STUB_${w}REASON:-}"
eval "ftype=\${CDKPF_STUB_${w}TYPE:-None}"
eval "cerr=\${CDKPF_STUB_${w}CREATE_ERR:-}"
eval "derr=\${CDKPF_STUB_${w}DESCRIBE_ERR:-}"
eval "dfails=\${CDKPF_STUB_${w}DESCRIBE_FAILS:-0}"
eval "dfrom=\${CDKPF_STUB_${w}DESCRIBE_FROM:-1}"
eval "eerr=\${CDKPF_STUB_${w}EVENTS_ERR:-}"
eval "wfail=\${CDKPF_STUB_${w}WAIT_FAIL:-}"
case "$args" in
  *"describe-stacks"*"StackStatus"*)
    n=$(cat "$CDKPF_STUB_CALLS.$w" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$CDKPF_STUB_CALLS.$w"
    [ -n "$derr" ] && [ "$n" -ge "$dfrom" ] && [ "$n" -le "$dfails" ] && { echo "$derr" >&2; exit 255; }
    echo "${status:-ROLLBACK_COMPLETE}" ;;
  *"describe-stack-events"*ResourceStatusReason*) [ -z "$eerr" ] || { echo "$eerr" >&2; exit 255; }; echo "$reason" ;;
  *"describe-stack-events"*ResourceType*) [ -z "$eerr" ] || { echo "$eerr" >&2; exit 255; }; echo "$ftype" ;;
  *"describe-stack-resources"*) echo "" ;;
  *"wait"*"stack-delete-complete"*) [ -z "$wfail" ] || exit 255 ;;
  *"create-stack"*) [ -z "$cerr" ] || { echo "$cerr" >&2; exit 254; } ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$tmp/aws"
printf '#!/bin/bash\nexit 0\n' > "$tmp/sleep"   # バックオフを実時間で待たない
chmod +x "$tmp/sleep"
export PATH="$tmp:$PATH" CDKPF_STUB_CALLS="$tmp/calls"

run() { # run <failed type> <reason> [--fail-only 以外を渡すと pass 側も回す] -> exit code
  rm -f "$tmp/calls" "$tmp/calls.F" "$tmp/calls.P"; : > "$tmp/calls"
  # 予算は保険。リトライの打ち切りが壊れたら 1 時間ではなく 1 分で落ちるように
  CDKPF_STUB_FTYPE="$1" CDKPF_STUB_FREASON="$2" CDKPF_REGION=us-east-1 CDKPF_POLL_BUDGET=60 \
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

echo "ok: verify-rule.sh scaffolding guard + create-stack rejection + unreadable status/events + leftover noise"
