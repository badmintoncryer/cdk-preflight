#!/bin/bash
# 実機再現ゲート: ルールの fail テンプレートが実際にデプロイ失敗し、
# pass テンプレートがデプロイ成功することを AWS 実環境で確認する。
# 使い方: bash bench/verify-rule.sh <rule-id> [--fail-only]
# リージョン: CDKPF_REGION > meta.yaml の benchRegion > ap-northeast-1
# exit: 0=verified / 2=BROKEN(fail が通った=制約ドリフト疑い)
#       3=pass 不成立（デプロイはされたが CREATE_COMPLETE 以外で終わった）/ 4=INCONCLUSIVE(判定不能)
# スタックは cdkpf-* 命名で作成し、必ず削除する。コストは失敗スタックのみで実質ゼロ。
set -u
cd "$(dirname "$0")/.."
RULE="${1:?usage: verify-rule.sh <rule-id> [--fail-only]}"
FAIL_ONLY="${2:-}"
DIR=$(find "${CDKPF_RULES_DIR:-rules}" -maxdepth 2 -type d -name "$RULE" | head -1) # 差し替えは自己テスト用
[ -z "$DIR" ] && { echo "rule not found: $RULE"; exit 1; }
META_REGION=$(grep -E '^benchRegion:' "$DIR/meta.yaml" | awk '{print $2}')
RTYPES=$(grep -E '^resourceTypes:' "$DIR/meta.yaml")
REGION="${CDKPF_REGION:-${META_REGION:-ap-northeast-1}}"
# repro.expect: fail の拒否文が逐語で含むべき断片（#264）。bundle-rules が 1 行のダブルクォート
# 文字列（" と \ を含まない）に縛っているので、YAML パーサの無い月次ランナーでも sed で読める。
EXPECT=$(sed -nE 's/^[[:space:]]+expect:[[:space:]]*"(.*)"[[:space:]]*$/\1/p' "$DIR/meta.yaml" | head -1)
mkdir -p bench/logs
LOG="bench/logs/$RULE.log"
: > "$LOG"
ERRF=$(mktemp)
trap 'rm -f "$ERRF"' EXIT

POLL_BUDGET_SECONDS=${CDKPF_POLL_BUDGET:-3600}

# aws CLI が非ゼロで返ったからといってスタックが無いとは限らない。スロットリングも
# 瞬断も期限切れの認証も同じ「非ゼロ」で、それを GONE に潰すと進行中のスタックを
# 消しにかかる（2026-09-22、4 並列で回していて pf-servicediscovery-* の 2 本が
# 進行中なのに GONE と報告され、cleanup が作成途中で消して証拠が消えた。片方は
# 直後の reason_of が理由を拾えていて、スタックが在ることが自分のログで裏取りできた）。
# 「無い」と言い切れるのは ValidationError がそう名指ししたときだけ。
stack_status() { # <stack> -> STATUS か GONE を stdout。読めなければ UNREADABLE と rc 1
  local st rc
  st=$(aws cloudformation describe-stacks --stack-name "$1" --region "$REGION" \
    --query "Stacks[0].StackStatus" --output text 2>"$ERRF")
  rc=$?
  # stderr は混ぜない: rc 0 でも警告が出ることがあり、混ぜると status に化けて
  # 終端判定をすり抜ける。
  [ "$rc" -eq 0 ] && { echo "$st"; return 0; }
  grep -qE 'ValidationError.*does not exist' "$ERRF" && { echo GONE; return 0; }
  cat "$ERRF" >> "$LOG"
  echo UNREADABLE
  return 1
}

poll_terminal() { # stack -> echo final status
  local stack=$1
  # 60 分。ElastiCache / MemoryDB のクラスタは作成にも削除にも 10-25 分かかるので 15 分では足りず
  # （2026-09-06 実測）、MSK の Provisioned クラスタは最小構成（kafka.t3.small × 2）でも
  # CREATE_COMPLETE まで 31m34s かかった（2026-09-13 実測）。
  # 予算は回数ではなく実時間で切る。1 周は sleep 10 に describe-stacks の往復が乗って実測 11 秒あり、
  # 旧実装の「180 回」は名目 30 分に対して実際は約 33 分だった。回数指定は API のレイテンシで
  # 予算がずれるうえ、ずれる方向がコメントと逆（名目より長い）なので当てにできない。
  local deadline=$(( $(date +%s) + POLL_BUDGET_SECONDS ))
  local unreadable=0 st
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if st=$(stack_status "$stack"); then
      unreadable=0
      case "$st" in
        CREATE_COMPLETE|CREATE_FAILED|ROLLBACK_COMPLETE|ROLLBACK_FAILED|GONE) echo "$st"; return ;;
      esac
    else
      # 読めないのはたいてい一過性なので、間隔を伸ばしながら数回だけ粘る。
      unreadable=$(( unreadable + 1 ))
      [ "$unreadable" -ge 5 ] && { echo UNREADABLE; return; }
      sleep $(( unreadable * 10 ))
      continue
    fi
    sleep 10
  done
  echo TIMEOUT
}

# イベント側も同じ落とし穴で、しかもこちらのほうが高くつく。読めなかったのか該当イベントが
# 無いのかが空文字に潰れると、下の足場ガードが無言で no-op になり、足場が倒れただけの
# ロールバックがそのまま "OK: verified" になる（= 嘘の証拠が meta.yaml に焼き付く）。
# 読めなかったことは戻り値で伝え、呼び出し側で判定を降りる。
# --output text は使わない。CLI は text のときだけクエリをページ（100 件）ごとに当てるので、イベントが
# 100 件を超えるスタックでは [-1] がページの数だけ答えを返し、どのページにも理由が無いと "None" が
# 複数行並んで 1 つの "None" と見分けられなくなる。json は全ページをまとめてから当てる（2026-09-27
# 実測、aws-cli 2.34: 116 件のスタックで length(StackEvents) が text は 100 と 16、json は 116）。
events_query() { # <stack> <jmespath> -> 値を stdout（null は None）。読めなければ rc 1
  local v
  v=$(aws cloudformation describe-stack-events --stack-name "$1" --region "$REGION" \
    --query "$2" --output json 2>"$ERRF")
  [ $? -eq 0 ] || { cat "$ERRF" >> "$LOG"; return 1; }
  python3 -c 'import json, sys; v = json.load(sys.stdin); print("None" if v is None else v)' <<<"$v"
}

# 最初に倒れたリソース。スタック自身の行は LogicalResourceId（= スタック名）で外す。ResourceType で
# 外していた頃は入れ子スタック（AWS::CloudFormation::Stack）の本物の失敗まで消え、隣のリソースの
# 巻き添えの "Resource creation cancelled" を理由として拾って verified にしていた（#264）。
root_failure() { echo "ResourceStatus=='CREATE_FAILED' && LogicalResourceId!='$1' && ResourceStatusReason!='Resource creation cancelled'"; }

# 理由を探す順: 最初に倒れたリソース → スタック自身の CREATE_FAILED（早期検証の失敗はここにしか
# 出ない）→ スタック自身の ROLLBACK_IN_PROGRESS（Outputs の Export のようにリソースに紐づかない
# 失敗は、既定のロールバックだとここにしか載らない。まとめ文は外す）。2026-09-26 に dev の実イベント
# 3,110 スタックで確かめた: 3 段目まで要るのは 3 本、2 段目で止まるのは 52 本。
reason_of() {
  local q r
  for q in "$(root_failure "$1")" "ResourceStatus=='CREATE_FAILED' && LogicalResourceId=='$1'" \
    "ResourceStatus=='ROLLBACK_IN_PROGRESS' && LogicalResourceId=='$1' && !starts_with(ResourceStatusReason || '', 'The following resource(s) failed to create')"; do
    r=$(events_query "$1" "StackEvents[?$q]|[-1].ResourceStatusReason") || return 1
    [ -n "$r" ] && [ "$r" != "None" ] && { echo "$r"; return 0; }
  done
  echo "$r"
}

failed_type() { events_query "$1" "StackEvents[?$(root_failure "$1")]|[-1].ResourceType"; }

# フィクスチャは検査対象の周りに足場（VPC、ロール、バケット）を建てる。足場のほうが
# 倒れた場合 — アカウントのクォータ、前回の消し残り、スロットリング — でもスタックは
# ROLLBACK_COMPLETE で終わるので、そのままだと「制約を再現した」と読めてしまい、
# 嘘の証拠が meta.yaml に焼き付く（2026-09-12、VPC のクォータで計算環境のルール 6 本が
# verified に見えた）。判定するのは「倒れたのがルールの対象型」か「上限系の文面ではない」
# ときだけにする。メッセージだけで見分けようとすると誤検出する: 名前の一意性を見る
# ルールは "already exists" が、ロールのアカウントを見るルールは "is not authorized" が
# 本物の証拠になる。文面の側は CloudFormation が空白なしの HandlerErrorCode: AlreadyExists でも
# 同じことを言うので両方拾う（2026-09-22、足場の HttpNamespace の衝突が素通りして verified になった）。
scaffolding_failure() { # <失敗したリソース型> <理由> -> 足場の失敗なら 0
  local ftype=$1 reason=$2
  case "$ftype" in "" | None) return 1 ;; esac
  grep -qF "$ftype" <<<"$RTYPES" && return 1
  grep -qiE 'maximum number of|LimitExceeded|limit exceeded|quota|Rate exceeded|Throttl|already ?exists' <<<"$reason"
}

cleanup() { # 無人運用前提: DELETE_FAILED で固着したら retain 削除まで自動で撃つ
  local stack=$1 st
  if st=$(stack_status "$stack"); then
    [ "$st" = GONE ] && return 0
  else
    # 状態が読めないだけで「消し終わった」ことにすると、課金物を黙って置き去りにする。
    # 在るか分からないときは消しにいく（無いスタックへの delete-stack は無害）。
    echo "cleanup: $stack ($REGION) status unreadable, deleting anyway" >> "$LOG"
  fi
  aws cloudformation delete-stack --stack-name "$stack" --region "$REGION" >>"$LOG" 2>&1
  aws cloudformation wait stack-delete-complete --stack-name "$stack" --region "$REGION" >>"$LOG" 2>&1 && return 0
  # wait が落ちた理由は DELETE_FAILED とは限らない（throttle でも落ちる）。LEFTOVER は
  # 消し残りの索引として読むものなので、消えているなら黙って抜ける。
  [ "$(stack_status "$stack")" = GONE ] && return 0
  local ids
  ids=$(aws cloudformation describe-stack-resources --stack-name "$stack" --region "$REGION" \
    --query "StackResources[?ResourceStatus=='DELETE_FAILED'].LogicalResourceId" --output text 2>>"$LOG")
  if [ -z "$ids" ] || [ "$ids" = "None" ]; then
    echo "LEFTOVER: $stack ($REGION) delete did not complete" | tee -a "$LOG"
    return 0
  fi
  aws cloudformation delete-stack --stack-name "$stack" --region "$REGION" --retain-resources $ids >>"$LOG" 2>&1
  if aws cloudformation wait stack-delete-complete --stack-name "$stack" --region "$REGION" >>"$LOG" 2>&1; then
    echo "LEFTOVER: $stack ($REGION) deleted with retained resources: $ids" | tee -a "$LOG"
  else
    echo "LEFTOVER: $stack ($REGION) still stuck after retain-delete: $ids" | tee -a "$LOG"
  fi
}

create_stack() { # <stack> <template> <fail|pass> — API レベルで弾かれたら理由を出して INCONCLUSIVE で抜ける
  local out rc msg
  out=$(aws cloudformation create-stack --stack-name "$1" --region "$REGION" \
    --template-body "file://$2" \
    --capabilities CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND --output text 2>&1)
  rc=$?
  echo "$out" >> "$LOG"
  [ "$rc" -eq 0 ] && return 0
  msg=$(tr '\n' ' ' <<<"$out")
  # 同期拒否は足場が倒れる余地が無いぶん一番強い証拠だが、throttle や認証切れと見分けられるのは
  # repro.expect を名指ししたときだけ（#264）。pass 側の同期拒否はフィクスチャが通らなかっただけ。
  if [ "$3" = fail ] && [ -n "$EXPECT" ] && grep -qF -- "$EXPECT" <<<"$msg"; then
    API_REJECTED=$msg
    return 0
  fi
  # 要約は 1 行に潰して両端を残す: templateBody の長さ超過はエラー文に弾かれたテンプレートが
  # まるごと載って複数行 52KB になり（2026-09-13、pf-batch-sp-share-distribution-max の pass）、
  # 頭だけ見ると型が、末尾だけ見ると "Member must have length less than or equal to 51200" が
  # 落ちる。全文は $LOG にある。
  [ ${#msg} -gt 400 ] && msg="${msg:0:200} […] ${msg: -200}"
  echo "!! INCONCLUSIVE: $3 create-stack API error: $msg" | tee -a "$LOG"
  cleanup "$1"
  exit 4
}

echo "=== $RULE: fail template ($REGION) ===" | tee -a "$LOG"
FSTACK="cdkpf-$RULE-fail"
API_REJECTED=
create_stack "$FSTACK" "$DIR/templates/fail.template.json" fail
READ_FAILED=0
if [ -n "$API_REJECTED" ]; then
  FSTATUS=API_REJECTED REASON=$API_REJECTED FTYPE=None
else
  FSTATUS=$(poll_terminal "$FSTACK")
  REASON=$(reason_of "$FSTACK") || READ_FAILED=1
  FTYPE=$(failed_type "$FSTACK") || READ_FAILED=1
fi
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
  UNREADABLE)
    echo "!! INCONCLUSIVE: could not read the fail stack's status — see $LOG" | tee -a "$LOG"
    exit 4 ;;
  GONE|TIMEOUT)
    echo "!! INCONCLUSIVE: fail stack ended $FSTATUS — cannot judge the constraint" | tee -a "$LOG"
    exit 4 ;;
esac
# ここまで来たのはスタックが倒れたとき。倒れた理由が読めないまま先に進むと、足場が倒れた
# だけのロールバックを足場ガードが素通しして verified になる。
if [ "$READ_FAILED" = 1 ]; then
  echo "!! INCONCLUSIVE: could not read the fail stack's events — the scaffolding guard cannot run" | tee -a "$LOG"
  exit 4
fi
# 倒れたことは証拠ではない。理由が読めない、または巻き添えの文しか無いまま OK を出していた
# （2026-09-25 の cloudformation の月次で 21 本中 5 本。#264）。
case "$REASON" in
  "" | None | "Resource creation cancelled" | "The following resource(s) failed to create"*)
    echo "!! INCONCLUSIVE: no reason on the fail stack names why it fell over (got: ${REASON:-empty})" | tee -a "$LOG"
    exit 4 ;;
esac
if [ -n "$EXPECT" ] && ! grep -qF -- "$EXPECT" <<<"$REASON"; then
  echo "!! INCONCLUSIVE: the fail stack fell for a different reason than repro.expect (\"$EXPECT\")" | tee -a "$LOG"
  exit 4
fi

if [ "$FAIL_ONLY" != "--fail-only" ]; then
  echo "=== $RULE: pass template ($REGION) ===" | tee -a "$LOG"
  PSTACK="cdkpf-$RULE-pass"
  create_stack "$PSTACK" "$DIR/templates/pass.template.json" pass
  PSTATUS=$(poll_terminal "$PSTACK")
  PREAD_FAILED=0
  PREASON=$(reason_of "$PSTACK") || PREAD_FAILED=1
  PTYPE=$(failed_type "$PSTACK") || PREAD_FAILED=1
  echo "pass: finalStatus=$PSTATUS" | tee -a "$LOG"
  echo "pass: reason=$PREASON" | tee -a "$LOG"
  cleanup "$PSTACK"
  if scaffolding_failure "$PTYPE" "$PREASON"; then
    echo "!! INCONCLUSIVE: the pass fixture's $PTYPE failed for a reason of its own: $PREASON" | tee -a "$LOG"
    exit 4
  fi
  [ "$PSTATUS" = UNREADABLE ] && { echo "!! INCONCLUSIVE: could not read the pass stack's status — see $LOG" | tee -a "$LOG"; exit 4; }
  if [ "$PSTATUS" != "CREATE_COMPLETE" ]; then
    [ "$PREAD_FAILED" = 1 ] && { echo "!! INCONCLUSIVE: could not read the pass stack's events — cannot tell a dirty fixture from a read error" | tee -a "$LOG"; exit 4; }
    echo "!! pass template failed to deploy — fixture is not clean" | tee -a "$LOG"
    exit 3
  fi
fi

echo "OK: $RULE verified (fail=$FSTATUS)" | tee -a "$LOG"
