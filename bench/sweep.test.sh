#!/bin/bash
# sweep.sh の残骸回収の自己チェック。aws をスタブに差し替えて実際の API は叩かない。
# 使い方: bash bench/sweep.test.sh
set -u
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/aws" <<'STUB'
#!/bin/bash
echo "$*" >> "$CDKPF_STUB_CALLS"
case "$1 $2" in
  "cloudformation list-stacks") echo "" ;;
  "cloudformation list-stack-sets") echo "${CDKPF_STUB_SS:-}" ;;
  # 1 回目だけ中身を返して空にする（delete-stack-instances 後に空になる非同期を模す）
  "cloudformation list-stack-instances")
    if [ -s "${CDKPF_STUB_SSI:-/dev/null}" ]; then cat "$CDKPF_STUB_SSI"; : > "$CDKPF_STUB_SSI"; fi ;;
  "cloudformation list-types") echo "${CDKPF_STUB_HOOKS:-}" ;;
  "resourcegroupstaggingapi get-resources") cat "$CDKPF_STUB_ORPHANS" ;;
  "kms describe-key") echo "${CDKPF_STUB_KEYSTATE:-Enabled}" ;;
  "route53resolver list-firewall-rule-groups") echo "${CDKPF_STUB_FRG:-}" ;;
  "s3api list-directory-buckets") case "$*" in *us-east-1*) echo "${CDKPF_STUB_DIRB:-}" ;; esac ;;
  "route53resolver list-firewall-rule-group-associations") echo "${CDKPF_STUB_FRGA:-}" ;;
  "route53resolver list-firewall-rules") printf '%b\n' "${CDKPF_STUB_FR:-}" ;;
  "route53resolver list-firewall-domain-lists") echo "${CDKPF_STUB_FDL:-}" ;;
  "globalaccelerator list-accelerators") echo "${CDKPF_STUB_GA:-}" ;;
  "globalaccelerator list-custom-routing-accelerators") echo "${CDKPF_STUB_GACR:-}" ;;
  "globalaccelerator list-listeners") echo "${CDKPF_STUB_GAL:-}" ;;
  "globalaccelerator list-endpoint-groups") echo "${CDKPF_STUB_GAEG:-}" ;;
  "globalaccelerator describe-accelerator") echo "${CDKPF_STUB_GASTATUS:-DEPLOYED}" ;;
  "iot list-domain-configurations") echo "${CDKPF_STUB_DC:-}" ;;
  "iot describe-domain-configuration") echo "${CDKPF_STUB_DCSTATUS:-ENABLED}" ;;
  # 削除の一覧と、グループ削除前の待ちの一覧は同じサブコマンドを叩く。待ちの方（starts_with 付き）は
  # 常に空を返して、スタブでも待ちループが 1 周で抜けるようにする
  "opensearchserverless list-collections")
    if [ -n "${CDKPF_STUB_AOSSDENY:-}" ]; then echo "An error occurred (AccessDeniedException): no aoss" >&2; exit 254; fi
    case "$*" in *starts_with*) ;; *) echo "${CDKPF_STUB_COLL:-}" ;; esac ;;
  "opensearchserverless list-collection-groups") echo "${CDKPF_STUB_CG:-}" ;;
  # --type ごとに呼ばれる。フィクスチャにある型だけ返す（回収行の本数を素直に数えられるように）
  "opensearchserverless list-security-policies")
    case "$*" in *"--type encryption"*) echo "${CDKPF_STUB_SP:-}" ;; esac ;;
  "opensearchserverless list-access-policies") echo "${CDKPF_STUB_AP:-}" ;;
  "opensearchserverless list-lifecycle-policies") echo "${CDKPF_STUB_LP:-}" ;;
  "opensearchserverless list-security-configs")
    case "$*" in *"--type saml"*) echo "${CDKPF_STUB_SCF:-}" ;; esac ;;
  "opensearchserverless list-vpc-endpoints") echo "${CDKPF_STUB_VPCE:-}" ;;
  *)
    if [ -n "${CDKPF_STUB_FAIL:-}" ] && grep -q -- "$CDKPF_STUB_FAIL" <<<"$*"; then
      echo "${CDKPF_STUB_ERR:-An error occurred: stub refused $2}" >&2; exit 254
    fi
    exit 0 ;;
esac
STUB
chmod +x "$tmp/aws"
export PATH="$tmp:$PATH"
export CDKPF_STUB_CALLS="$tmp/calls"

run() { # run <orphans-file> — sweep を 1 回まわし、出力を返す。呼び出しログは $tmp/calls
  export CDKPF_STUB_ORPHANS="$1"
  : > "$CDKPF_STUB_CALLS"
  bash bench/sweep.sh
}
fail() { echo "FAIL: $1"; echo "--- out ---"; echo "${2:-}"; echo "--- calls ---"; cat "$CDKPF_STUB_CALLS"; exit 1; }
called() { grep -q -- "$1" "$CDKPF_STUB_CALLS"; }

: > "$tmp/none"
out=$(run "$tmp/none")
grep -q LEFTOVER <<<"$out" && fail "clean account reported a leftover" "$out"

# 既知の種別は回収され、LEFTOVER に落ちない
printf 'arn:aws:ecs:ap-northeast-1:1:cluster/c1\tarn:aws:ecs:ap-northeast-1:1:task-definition/t1:1\tarn:aws:cognito-idp:ap-northeast-1:1:userpool/ap-northeast-1_abc\tarn:aws:kms:ap-northeast-1:1:key/k1\tarn:aws:dynamodb:ap-northeast-1:1:table/tbl1/stream/2026-09-06T11:32:34.629\n' > "$tmp/known"
out=$(run "$tmp/known")
grep -q LEFTOVER <<<"$out" && fail "a reclaimable orphan was reported as leftover" "$out"
[ "$(grep -c '^sweep: reclaimed' <<<"$out")" -eq 15 ] || fail "expected 15 reclaim lines (5 arns x 3 regions)" "$out"
called 'ecs delete-cluster --cluster arn:aws:ecs:ap-northeast-1:1:cluster/c1' || fail "cluster not deleted"
called 'ecs delete-task-definitions --task-definitions arn:aws:ecs:ap-northeast-1:1:task-definition/t1:1' || fail "task definition not deleted"
called 'cognito-idp delete-user-pool --user-pool-id ap-northeast-1_abc' || fail "user pool not deleted"
called 'kms schedule-key-deletion --key-id arn:aws:kms:ap-northeast-1:1:key/k1 --region ap-northeast-1 --pending-window-in-days 7' || fail "key deletion not scheduled"
called 'dynamodb delete-table --table-name tbl1' || fail "table not deleted (stream arn must resolve to its table)"

# 削除待ちの KMS キーは二度スケジュールせず、LEFTOVER にも落とさない
printf 'arn:aws:kms:ap-northeast-1:1:key/k1\n' > "$tmp/pending"
export CDKPF_STUB_KEYSTATE=PendingDeletion
out=$(run "$tmp/pending")
unset CDKPF_STUB_KEYSTATE
grep -q LEFTOVER <<<"$out" && fail "a key already pending deletion was reported as leftover" "$out"
called 'schedule-key-deletion' && fail "re-scheduled a key that is already pending deletion" "$out"

# 未知の種別は今まで通り LEFTOVER で報告する
printf 'arn:aws:ec2:ap-northeast-1:1:natgateway/nat-1\n' > "$tmp/unknown"
out=$(run "$tmp/unknown")
[ "$(grep -c '^LEFTOVER: orphaned resource' <<<"$out")" -eq 3 ] || fail "expected 3 leftover lines (1 arn x 3 regions)" "$out"
grep -q 'nat-1 (ap-northeast-1)' <<<"$out" || fail "arn/region not reported" "$out"

# 削除が失敗したものは LEFTOVER に落ちる
printf 'arn:aws:cognito-idp:ap-northeast-1:1:userpool/ap-northeast-1_abc\n' > "$tmp/failing"
export CDKPF_STUB_FAIL=delete-user-pool
out=$(run "$tmp/failing")
unset CDKPF_STUB_FAIL
[ "$(grep -c '^LEFTOVER: orphaned resource' <<<"$out")" -eq 3 ] || fail "a failed deletion was not reported" "$out"
grep -q 'could not delete: .*stub refused' <<<"$out" || fail "the failure reason was not carried onto the leftover line" "$out"

# 既に消えているものは回収済み扱い（タグ索引の残骸で毎月 LEFTOVER が出るのを防ぐ）
export CDKPF_STUB_FAIL=delete-user-pool CDKPF_STUB_ERR='An error occurred (ResourceNotFoundException) when calling the DeleteUserPool operation: User pool does not exist'
out=$(run "$tmp/failing")
unset CDKPF_STUB_FAIL CDKPF_STUB_ERR
grep -q LEFTOVER <<<"$out" && fail "an already-deleted resource was reported as leftover" "$out"

# CloudFormation が消し残す DNS Firewall の残骸を、参照される順に消す
export CDKPF_STUB_FRG=rg-1 CDKPF_STUB_FRGA=ra-1 CDKPF_STUB_FR='dl-1\tA\ndl-2\tNone' CDKPF_STUB_FDL=dl-1
out=$(run "$tmp/none")
grep -q LEFTOVER <<<"$out" && fail "a reclaimable firewall orphan was reported as leftover" "$out"
[ "$(grep -c 'reclaimed orphaned firewall' <<<"$out")" -eq 6 ] || fail "expected 6 firewall reclaim lines (group + list x 3 regions)" "$out"
called 'disassociate-firewall-rule-group --firewall-rule-group-association-id ra-1' || fail "association not removed"
# qtype 付きのルールは --qtype まで渡さないと消えない。qtype 無しの行に --qtype を付けても落ちる
called 'delete-firewall-rule --firewall-rule-group-id rg-1 --firewall-domain-list-id dl-1 --qtype A' || fail "qtype not passed through"
called 'delete-firewall-rule --firewall-rule-group-id rg-1 --firewall-domain-list-id dl-2 --region' || fail "qtype-less rule not deleted plainly"
[ "$(grep -n 'delete-firewall-rule --' "$CDKPF_STUB_CALLS" | head -1 | cut -d: -f1)" \
  -lt "$(grep -n 'delete-firewall-rule-group --' "$CDKPF_STUB_CALLS" | head -1 | cut -d: -f1)" ] ||
  fail "rules must be deleted before the group ([RSLVR-02103])" "$out"

export CDKPF_STUB_FAIL=delete-firewall-domain-list
out=$(run "$tmp/none")
unset CDKPF_STUB_FAIL CDKPF_STUB_FRG CDKPF_STUB_FRGA CDKPF_STUB_FR CDKPF_STUB_FDL
[ "$(grep -c '^LEFTOVER: orphaned firewall domain list' <<<"$out")" -eq 3 ] || fail "a failed firewall deletion was not reported" "$out"

# Global Accelerator は時間課金（有効・無効に関わらず $0.025/h）で、リージョンループにもタグ索引にも
# 載らない。依存の順（endpoint group → listener → accelerator）に消し、削除前に無効化する
export CDKPF_STUB_GA=ga-1 CDKPF_STUB_GAL=lsn-1 CDKPF_STUB_GAEG=eg-1
out=$(run "$tmp/none")
grep -q LEFTOVER <<<"$out" && fail "a reclaimable accelerator was reported as leftover" "$out"
[ "$(grep -c 'reclaimed orphaned accelerator' <<<"$out")" -eq 1 ] || fail "expected 1 accelerator reclaim line (GA is global, not per region)" "$out"
called 'globalaccelerator delete-endpoint-group --endpoint-group-arn eg-1' || fail "endpoint group not deleted"
called 'globalaccelerator delete-listener --listener-arn lsn-1' || fail "listener not deleted"
called 'globalaccelerator update-accelerator --accelerator-arn ga-1 --no-enabled' || fail "accelerator not disabled before delete"
[ "$(grep -n 'globalaccelerator delete-listener' "$CDKPF_STUB_CALLS" | head -1 | cut -d: -f1)" \
  -lt "$(grep -n 'globalaccelerator delete-accelerator' "$CDKPF_STUB_CALLS" | head -1 | cut -d: -f1)" ] ||
  fail "listeners must be deleted before the accelerator" "$out"
[ "$(grep -n 'update-accelerator .*--no-enabled' "$CDKPF_STUB_CALLS" | head -1 | cut -d: -f1)" \
  -lt "$(grep -n 'globalaccelerator delete-accelerator' "$CDKPF_STUB_CALLS" | head -1 | cut -d: -f1)" ] ||
  fail "an enabled accelerator cannot be deleted; disable must come first" "$out"

# 消せなかった accelerator は時間課金なので LEFTOVER に落として金額まで出す
export CDKPF_STUB_FAIL=delete-accelerator
out=$(run "$tmp/none")
unset CDKPF_STUB_FAIL
grep -q 'LEFTOVER: orphaned accelerator ga-1 (us-west-2, \$0.025/h)' <<<"$out" || fail "a failed accelerator deletion was not reported with its hourly cost" "$out"
unset CDKPF_STUB_GA CDKPF_STUB_GAL CDKPF_STUB_GAEG

# カスタムルーティングは自動削除しないが、見えなくはしない
export CDKPF_STUB_GACR=cr-1
out=$(run "$tmp/none")
unset CDKPF_STUB_GACR
grep -q 'LEFTOVER: orphaned custom routing accelerator cr-1' <<<"$out" || fail "a custom routing accelerator was not reported" "$out"

# StackSet はスタックを消しても残り、翌月は already exists で落ちるのに
# AWS::CloudFormation::StackSet が resourceTypes にあるせいで verified と報告される。
# インスタンスが残っていると delete-stack-set が拒否するので先に落とす
export CDKPF_STUB_SS=cdkpf73-ssft-f
printf '111111111111\tus-east-1\n' > "$tmp/ssi"
export CDKPF_STUB_SSI="$tmp/ssi"
out=$(run "$tmp/none")
grep -q LEFTOVER <<<"$out" && fail "a reclaimable stack set was reported as leftover" "$out"
[ "$(grep -c 'reclaimed orphaned stack set' <<<"$out")" -eq 3 ] || fail "expected 3 stack set reclaim lines (1 x 3 regions)" "$out"
called 'delete-stack-instances --stack-set-name cdkpf73-ssft-f --region ap-northeast-1 --accounts 111111111111 --regions us-east-1 --no-retain-stacks' || fail "instances not deleted before the stack set"
[ "$(grep -n 'delete-stack-instances' "$CDKPF_STUB_CALLS" | head -1 | cut -d: -f1)" \
  -lt "$(grep -n 'delete-stack-set' "$CDKPF_STUB_CALLS" | head -1 | cut -d: -f1)" ] ||
  fail "a stack set with instances cannot be deleted; instances must go first" "$out"

# インスタンスが無ければ delete-stack-instances は呼ばない
: > "$tmp/ssi"
out=$(run "$tmp/none")
called 'delete-stack-instances' && fail "called delete-stack-instances for an empty stack set" "$out"
[ "$(grep -c 'reclaimed orphaned stack set' <<<"$out")" -eq 3 ] || fail "an empty stack set was not reclaimed" "$out"

export CDKPF_STUB_FAIL=delete-stack-set
out=$(run "$tmp/none")
unset CDKPF_STUB_FAIL CDKPF_STUB_SS CDKPF_STUB_SSI
[ "$(grep -c '^LEFTOVER: orphaned stack set' <<<"$out")" -eq 3 ] || fail "a failed stack set deletion was not reported" "$out"

# Hook 型は deregister-type が "Third party types can't be deregistered" で拒否するので
# deactivate-type で消す
export CDKPF_STUB_HOOKS=Private::Guard::Cdkpf73Fail
out=$(run "$tmp/none")
grep -q LEFTOVER <<<"$out" && fail "a reclaimable hook type was reported as leftover" "$out"
called 'deactivate-type --type HOOK --type-name Private::Guard::Cdkpf73Fail' || fail "hook type not deactivated"
called 'deregister-type' && fail "deregister-type is refused for third party types; deactivate-type is the one that works" "$out"

export CDKPF_STUB_FAIL=deactivate-type
out=$(run "$tmp/none")
unset CDKPF_STUB_FAIL CDKPF_STUB_HOOKS
[ "$(grep -c '^LEFTOVER: orphaned hook type' <<<"$out")" -eq 3 ] || fail "a failed hook type deactivation was not reported" "$out"

# IoT の DomainConfiguration は名前がリージョン一意で、AWS マネージドのものは DISABLED に
# してから 7 日経たないと消せない。CFN はスタック削除時にこれで転ぶので孤児が残り、
# 翌月の再検証が同じ名前で ResourceAlreadyExists になる
export CDKPF_STUB_DC=arn:aws:iot:us-east-1:1:domainconfiguration/cdkpf270dc6/wlfxr
out=$(run "$tmp/none")
grep -q LEFTOVER <<<"$out" && fail "a reclaimable domain configuration was reported as leftover" "$out"
[ "$(grep -c 'reclaimed orphaned domain configuration' <<<"$out")" -eq 3 ] ||
  fail "expected 3 domain configuration reclaim lines (1 x 3 regions)" "$out"
called "starts_with(domainConfigurationName,'cdkpf')" ||
  fail "the cdkpf filter is what keeps iot:Data-ATS (the account data endpoint) out of the sweep" "$out"
called 'iot update-domain-configuration --domain-configuration-name cdkpf270dc6' ||
  fail "an ENABLED domain configuration was not disabled first" "$out"
called 'iot delete-domain-configuration --domain-configuration-name cdkpf270dc6' ||
  fail "domain configuration not deleted" "$out"

# DISABLED のものに DISABLED を書き直すと lastStatusChangeDate が動いて 7 日が永遠に来ない
export CDKPF_STUB_DCSTATUS=DISABLED
out=$(run "$tmp/none")
unset CDKPF_STUB_DCSTATUS
called 'iot update-domain-configuration' &&
  fail "re-disabling a DISABLED configuration restarts the 7 day clock" "$out"

# 7 日待ちの拒否は消せる回が来るまで毎月出る。LEFTOVER にすると report.sh が毎月 issue を立てる
export CDKPF_STUB_FAIL=delete-domain-configuration
export CDKPF_STUB_ERR='An error occurred (InvalidRequestException): AWS Managed Domain Configuration must be disabled for at least 7 days before it can be deleted'
out=$(run "$tmp/none")
grep -q LEFTOVER <<<"$out" && fail "the 7 day wait is expected and must not be reported as leftover" "$out"

# それ以外の失敗は見えなくしない
export CDKPF_STUB_ERR='An error occurred (ThrottlingException): Rate exceeded'
out=$(run "$tmp/none")
unset CDKPF_STUB_FAIL CDKPF_STUB_ERR CDKPF_STUB_DC
[ "$(grep -c '^LEFTOVER: orphaned domain configuration' <<<"$out")" -eq 3 ] ||
  fail "a failed domain configuration deletion was not reported" "$out"

# OpenSearch Serverless は課金物（コレクション / コレクショングループ）を建てるのに回収経路が無かった。
# スタックタグは AOSS に伝播しないのでタグ索引では拾えず、名前で引く
export CDKPF_STUB_CG=$'cg-1\tcdkpf-cg-minmax'
out=$(run "$tmp/none")
grep -q LEFTOVER <<<"$out" && fail "a reclaimable collection group was reported as leftover" "$out"
[ "$(grep -c 'reclaimed orphaned aoss collection group' <<<"$out")" -eq 3 ] ||
  fail "expected 3 collection group reclaim lines (1 x 3 regions)" "$out"
called 'opensearchserverless delete-collection-group --id cg-1' || fail "collection group not deleted" "$out"

# コレクションが 1 枚でも残っているとグループの削除が拒否されるので、コレクションを先に消す
export CDKPF_STUB_COLL=$'c-1\tcdkpf-c1'
out=$(run "$tmp/none")
grep -q LEFTOVER <<<"$out" && fail "a reclaimable collection was reported as leftover" "$out"
called 'opensearchserverless delete-collection --id c-1' || fail "collection not deleted" "$out"
[ "$(grep -n 'delete-collection --id' "$CDKPF_STUB_CALLS" | head -1 | cut -d: -f1)" \
  -lt "$(grep -n 'delete-collection-group --id' "$CDKPF_STUB_CALLS" | head -1 | cut -d: -f1)" ] ||
  fail "a group holding collections cannot be deleted; collections must go first" "$out"

# cdkpf- が付いていないものは消さない（#268 のフィクスチャは Collection が probe-*、
# ポリシー類が enc-* / sc-* で接頭辞を持たない）。ただし見えなくはしない
export CDKPF_STUB_COLL=$'c-2\tprobe-mismatch'
out=$(run "$tmp/none")
called 'opensearchserverless delete-collection --id c-2' &&
  fail "deleted a collection that is not a cdkpf- fixture" "$out"
[ "$(grep -c '^LEFTOVER: orphaned aoss collection probe-mismatch' <<<"$out")" -eq 3 ] ||
  fail "a non-cdkpf collection must still be reported" "$out"
grep -q 'LEFTOVER: orphaned aoss collection probe-mismatch (c-2) (ap-northeast-1, \$0.5〜1/h)' <<<"$out" ||
  fail "the collection leftover line must carry its hourly cost" "$out"
unset CDKPF_STUB_COLL CDKPF_STUB_CG

# 削除の失敗は理由ごと LEFTOVER に落ちる
export CDKPF_STUB_CG=$'cg-1\tcdkpf-cg-minmax' CDKPF_STUB_FAIL=delete-collection-group
out=$(run "$tmp/none")
unset CDKPF_STUB_FAIL CDKPF_STUB_CG
[ "$(grep -c '^LEFTOVER: orphaned aoss collection group' <<<"$out")" -eq 3 ] ||
  fail "a failed collection group deletion was not reported" "$out"
grep -q 'could not delete: .*stub refused' <<<"$out" ||
  fail "the failure reason was not carried onto the collection group leftover line" "$out"

# $0 の帯。消し残すと翌月の同名フィクスチャが already exists で落ち、制約とは別の理由の失敗になる
export CDKPF_STUB_SP=cdkpf-enc CDKPF_STUB_AP=cdkpf-ap CDKPF_STUB_LP=cdkpf-lc CDKPF_STUB_VPCE=$'vpce-1\tcdkpf-vpce'
out=$(run "$tmp/none")
grep -q LEFTOVER <<<"$out" && fail "a reclaimable aoss policy was reported as leftover" "$out"
called 'delete-security-policy --type encryption --name cdkpf-enc' || fail "encryption policy not deleted" "$out"
called 'delete-access-policy --type data --name cdkpf-ap' || fail "access policy not deleted" "$out"
called 'delete-lifecycle-policy --type retention --name cdkpf-lc' || fail "lifecycle policy not deleted" "$out"
called 'delete-vpc-endpoint --id vpce-1' || fail "vpc endpoint not deleted" "$out"
export CDKPF_STUB_SP=enc-dup-1
out=$(run "$tmp/none")
called 'delete-security-policy' && fail "deleted a policy that is not a cdkpf- fixture" "$out"
[ "$(grep -c '^LEFTOVER: orphaned aoss encryption policy enc-dup-1' <<<"$out")" -eq 3 ] ||
  fail "a non-cdkpf encryption policy must still be reported" "$out"
unset CDKPF_STUB_SP CDKPF_STUB_AP CDKPF_STUB_LP CDKPF_STUB_VPCE

# SecurityConfig は summaries に name が無く、id が <type>/<account>/<name>。
# 接頭辞は最後のセグメントで見る（真ん中はアカウント ID なので starts_with では引けない）
export CDKPF_STUB_SCF=saml/111111111111/cdkpf-sc
out=$(run "$tmp/none")
grep -q LEFTOVER <<<"$out" && fail "a reclaimable security config was reported as leftover" "$out"
called 'delete-security-config --id saml/111111111111/cdkpf-sc' || fail "security config not deleted" "$out"
export CDKPF_STUB_SCF=saml/111111111111/sc-md-a
out=$(run "$tmp/none")
called 'delete-security-config' && fail "deleted a security config that is not a cdkpf- fixture" "$out"
[ "$(grep -c '^LEFTOVER: orphaned aoss saml security config' <<<"$out")" -eq 3 ] ||
  fail "a non-cdkpf security config must still be reported" "$out"
unset CDKPF_STUB_SCF

# 一覧が権限で落ちたら、空のアカウントと同じ顔をせずに LEFTOVER で言う。月次は別アカウントの
# ロールで走るので、aoss:List* が無いと回収経路まるごとが黙って空振りする
export CDKPF_STUB_AOSSDENY=1 CDKPF_STUB_CG=$'cg-1\tcdkpf-cg-minmax'
out=$(run "$tmp/none")
unset CDKPF_STUB_AOSSDENY CDKPF_STUB_CG
[ "$(grep -c '^LEFTOVER: aoss sweep could not list anything' <<<"$out")" -eq 3 ] ||
  fail "a denied aoss list must be reported, not read as an empty account" "$out"
grep -q 'could not list anything (ap-northeast-1) — .*AccessDenied' <<<"$out" ||
  fail "the denial reason was not carried onto the leftover line" "$out"
called 'delete-collection-group' &&
  fail "kept deleting after the list was denied (the listing is what the deletes are based on)" "$out"

# ロールバックで消えないディレクトリバケットは名前で拾う（タグ索引にも list-buckets にも出ない）
export CDKPF_STUB_DIRB=cdkpf-s3xlnaf-b0--use1-az4--x-s3
out=$(run "$tmp/none")
unset CDKPF_STUB_DIRB
grep -q 'reclaimed directory bucket cdkpf-s3xlnaf-b0--use1-az4--x-s3 (us-east-1)' <<<"$out" ||
  fail "an orphaned directory bucket was not reclaimed" "$out"
called 'delete-bucket --bucket cdkpf-s3xlnaf-b0--use1-az4--x-s3 --region us-east-1' ||
  fail "the directory bucket was not deleted in its region" "$out"

echo "sweep.test.sh: OK"
