#!/bin/bash
# cdkpf-* 残存スタックの全掃除。DELETE_FAILED は retain 削除まで自動で撃ち、
# 回収しきれなかったものは "LEFTOVER:" 行で報告する（report.sh が拾う）。
set -u

# 失敗した回収の理由。LEFTOVER 行に載せる（載せないと次の分岐を足すのに実行のやり直しが要る）
RECLAIM_ERR=$(mktemp)
trap 'rm -f "$RECLAIM_ERR"' EXIT

# タグ孤児を種別ごとに回収する。消せた（か既に消えていた）なら 0、それ以外は非 0。
# 分岐は実際に残骸が出た種別にだけ足すこと。未知の種別は 1 を返して LEFTOVER 行に落ちる。
reclaim() {
  local arn=$1 region=$2 svc res name
  svc=$(cut -d: -f3 <<<"$arn")
  res=$(cut -d: -f6- <<<"$arn")
  : > "$RECLAIM_ERR"
  case "$svc/${res%%/*}" in
    ecs/cluster)
      aws ecs delete-cluster --cluster "$arn" --region "$region" >/dev/null ;;
    ecs/task-definition)
      aws ecs deregister-task-definition --task-definition "$arn" --region "$region" >/dev/null
      aws ecs delete-task-definitions --task-definitions "$arn" --region "$region" >/dev/null ;;
    cognito-idp/userpool)
      aws cognito-idp delete-user-pool --user-pool-id "${res#*/}" --region "$region" >/dev/null ;;
    kms/key)
      # 削除は最短 7 日待ちで即時には消えない。待機中のキーは回収済みとして扱う
      # （そうしないと「消したのに毎月 LEFTOVER で上がる」が 7 日間続く）
      [ "$(aws kms describe-key --key-id "$arn" --region "$region" \
            --query KeyMetadata.KeyState --output text)" = PendingDeletion ] ||
        aws kms schedule-key-deletion --key-id "$arn" --region "$region" \
          --pending-window-in-days 7 >/dev/null ;;
    dynamodb/table)
      # stream 単体は消せないので、ARN からテーブル名を切り出してテーブルごと消す
      name=${res#table/}; name=${name%%/*}
      aws dynamodb delete-table --table-name "$name" --region "$region" >/dev/null ;;
    iot/domainconfiguration)
      # AWS マネージドの構成は「DISABLED にしてから 7 日」経たないと消せない（2026-09-25 us-east-1 実測:
      # InvalidRequestException: AWS Managed Domain Configuration must be disabled for at least 7 days
      # before it can be deleted）。毎回無条件に DISABLED を書くと lastStatusChangeDate が動いて
      # 7 日が永遠に来ないので、ENABLED のときだけ落とす。あとは待つだけなので下の grep で回収済み扱い
      name=${res#domainconfiguration/}; name=${name%%/*}
      [ "$(aws iot describe-domain-configuration --domain-configuration-name "$name" \
            --region "$region" --query domainConfigurationStatus --output text)" = ENABLED ] &&
        aws iot update-domain-configuration --domain-configuration-name "$name" \
          --region "$region" --domain-configuration-status DISABLED >/dev/null
      aws iot delete-domain-configuration --domain-configuration-name "$name" \
        --region "$region" >/dev/null ;;
    *) return 1 ;;
  esac 2>"$RECLAIM_ERR" && return 0
  # タグ索引には既に消えたリソースの行が残ることがある（Cognito のプールは削除後も、
  # ECS のクラスタは INACTIVE のまま返る）。存在しないものは回収済みとして扱う
  grep -qE 'NotFoundException|does not exist|disabled for at least 7 days' "$RECLAIM_ERR"
}

# 失敗理由を 1 行に畳んで返す。取れなかったら手作業を促す既定文
reclaim_err() {
  local msg
  msg=$(tr -s '\n\t' '  ' < "$RECLAIM_ERR" | head -c 300)
  echo "${msg:-remove by hand}"
}

# CloudFormation はスタックを消しても DNS Firewall のルールグループとドメインリストを残す
# （2026-09-11 us-east-1 で実測: cdkpf-* スタックが 0 の状態でルールグループ 13 / ドメインリスト 3 が生存）。
# スタック名にもタグにも引っかからないので上の 2 つでは拾えない。フィクスチャ側が付ける
# cdkpf- 接頭辞で拾い、rule → group → domain list の順に消す（逆順だと参照で消せない）。
sweep_dns_firewall() {
  local region=$1 id a dlid qtype
  aws route53resolver list-firewall-rule-groups --region "$region" \
    --query "FirewallRuleGroups[?starts_with(Name,'cdkpf-')].Id" --output text 2>/dev/null |
    tr '\t' '\n' | while read -r id; do
    [ -z "$id" ] || [ "$id" = "None" ] && continue
    aws route53resolver list-firewall-rule-group-associations --region "$region" \
      --firewall-rule-group-id "$id" --query 'FirewallRuleGroupAssociations[].Id' --output text 2>/dev/null |
      tr '\t' '\n' | while read -r a; do
      [ -z "$a" ] || [ "$a" = "None" ] && continue
      aws route53resolver disassociate-firewall-rule-group --firewall-rule-group-association-id "$a" \
        --region "$region" >/dev/null 2>&1
    done
    # ルールが 1 本でも残っていると [RSLVR-02103] でグループを消せない。qtype 付きのルールは
    # --qtype まで一致させないと消えない（ドメインリスト ID だけでは ValidationException）
    aws route53resolver list-firewall-rules --firewall-rule-group-id "$id" --region "$region" \
      --query 'FirewallRules[].[FirewallDomainListId,Qtype]' --output text 2>/dev/null |
      while IFS=$'\t' read -r dlid qtype; do
      [ -z "$dlid" ] || [ "$dlid" = "None" ] && continue
      if [ -n "$qtype" ] && [ "$qtype" != "None" ]; then
        aws route53resolver delete-firewall-rule --firewall-rule-group-id "$id" \
          --firewall-domain-list-id "$dlid" --qtype "$qtype" --region "$region" >/dev/null 2>&1
      else
        aws route53resolver delete-firewall-rule --firewall-rule-group-id "$id" \
          --firewall-domain-list-id "$dlid" --region "$region" >/dev/null 2>&1
      fi
    done
    if aws route53resolver delete-firewall-rule-group --firewall-rule-group-id "$id" \
         --region "$region" 2>"$RECLAIM_ERR" >/dev/null; then
      echo "sweep: reclaimed orphaned firewall rule group $id ($region)"
    else
      echo "LEFTOVER: orphaned firewall rule group $id ($region) — could not delete: $(reclaim_err)"
    fi
  done
  aws route53resolver list-firewall-domain-lists --region "$region" \
    --query "FirewallDomainLists[?starts_with(Name,'cdkpf-')].Id" --output text 2>/dev/null |
    tr '\t' '\n' | while read -r id; do
    [ -z "$id" ] || [ "$id" = "None" ] && continue
    if aws route53resolver delete-firewall-domain-list --firewall-domain-list-id "$id" \
         --region "$region" 2>"$RECLAIM_ERR" >/dev/null; then
      echo "sweep: reclaimed orphaned firewall domain list $id ($region)"
    else
      echo "LEFTOVER: orphaned firewall domain list $id ($region) — could not delete: $(reclaim_err)"
    fi
  done
}

# Global Accelerator は us-west-2 固定のグローバルサービス（accelerator の ARN はリージョン欄が空）で、
# 下のタグ索引には載らない。有効・無効に関わらず 1 時間ごと（部分時間も 1 時間として）$0.025 かかるので、
# 消し残すと気づかないまま積み上がる。名前の cdkpf- 接頭辞で拾い、
# endpoint group → listener → accelerator の順に消す（依存があるので逆順では消せない）。
sweep_global_accelerator() {
  local arn lsn eg i st
  aws globalaccelerator list-accelerators --region us-west-2 \
    --query "Accelerators[?starts_with(Name,'cdkpf-')].AcceleratorArn" --output text 2>/dev/null |
    tr '\t' '\n' | while read -r arn; do
    [ -z "$arn" ] || [ "$arn" = "None" ] && continue
    aws globalaccelerator list-listeners --accelerator-arn "$arn" --region us-west-2 \
      --query 'Listeners[].ListenerArn' --output text 2>/dev/null | tr '\t' '\n' | while read -r lsn; do
      [ -z "$lsn" ] || [ "$lsn" = "None" ] && continue
      aws globalaccelerator list-endpoint-groups --listener-arn "$lsn" --region us-west-2 \
        --query 'EndpointGroups[].EndpointGroupArn' --output text 2>/dev/null | tr '\t' '\n' | while read -r eg; do
        [ -z "$eg" ] || [ "$eg" = "None" ] && continue
        aws globalaccelerator delete-endpoint-group --endpoint-group-arn "$eg" --region us-west-2 >/dev/null 2>&1
      done
      aws globalaccelerator delete-listener --listener-arn "$lsn" --region us-west-2 >/dev/null 2>&1
    done
    # 有効なままでは消せない。無効化は非同期なので Status が DEPLOYED に戻るまで待つ（実測で数分）
    aws globalaccelerator update-accelerator --accelerator-arn "$arn" --no-enabled --region us-west-2 >/dev/null 2>&1
    for i in $(seq 40); do
      st=$(aws globalaccelerator describe-accelerator --accelerator-arn "$arn" --region us-west-2 \
        --query Accelerator.Status --output text 2>/dev/null)
      [ "$st" = DEPLOYED ] && break
      sleep 15
    done
    if aws globalaccelerator delete-accelerator --accelerator-arn "$arn" --region us-west-2 \
         2>"$RECLAIM_ERR" >/dev/null; then
      echo "sweep: reclaimed orphaned accelerator $arn (us-west-2)"
    else
      echo "LEFTOVER: orphaned accelerator $arn (us-west-2, \$0.025/h) — could not delete: $(reclaim_err)"
    fi
  done
  # カスタムルーティングはフィクスチャで使っていない。出たときに見えるようにだけしておく
  aws globalaccelerator list-custom-routing-accelerators --region us-west-2 \
    --query "Accelerators[?starts_with(Name,'cdkpf-')].AcceleratorArn" --output text 2>/dev/null |
    tr '\t' '\n' | while read -r arn; do
    [ -z "$arn" ] || [ "$arn" = "None" ] && continue
    echo "LEFTOVER: orphaned custom routing accelerator $arn (us-west-2, \$0.025/h) — remove by hand"
  done
}

# CloudFormation はスタックを消しても StackSet を残す。StackSet を作る fail フィクスチャは
# ROLLBACK_FAILED で終わるので cleanup() が StackSet を retain し、スタックだけが消えて
# 固定名の StackSet が孤児になる。翌月の同じフィクスチャは「already exists」で落ちるが、
# AWS::CloudFormation::StackSet はそのルールの resourceTypes に載っているため
# scaffolding_failure() が足場の失敗と見なさず、別の理由で落ちたのに verified と報告される
# （2026-09-25、#73 のテンプレート層ルールで実測）。インスタンスが残っていると delete-stack-set が
# 拒否するので、先に delete-stack-instances で落としてから消す。
sweep_stack_sets() {
  local region=$1 ss inst accts regs i
  aws cloudformation list-stack-sets --region "$region" --status ACTIVE --no-paginate \
    --query "Summaries[?starts_with(StackSetName,'cdkpf')].StackSetName" --output text 2>/dev/null |
    tr '\t' '\n' | while read -r ss; do
    [ -z "$ss" ] || [ "$ss" = "None" ] && continue
    inst=$(aws cloudformation list-stack-instances --stack-set-name "$ss" --region "$region" \
      --query 'Summaries[].[Account,Region]' --output text 2>/dev/null)
    accts=$(awk 'NF{print $1}' <<<"$inst" | sort -u | tr '\n' ' ')
    regs=$(awk 'NF{print $2}' <<<"$inst" | sort -u | tr '\n' ' ')
    if [ -n "${accts// /}" ]; then
      aws cloudformation delete-stack-instances --stack-set-name "$ss" --region "$region" \
        --accounts $accts --regions $regs --no-retain-stacks >/dev/null 2>&1
      # インスタンス削除は非同期。空になるまで待たないと delete-stack-set が not empty で拒否する
      for i in $(seq 30); do
        [ -z "$(aws cloudformation list-stack-instances --stack-set-name "$ss" --region "$region" \
              --query 'Summaries[].Account' --output text 2>/dev/null)" ] && break
        sleep 10
      done
    fi
    if aws cloudformation delete-stack-set --stack-set-name "$ss" --region "$region" \
         2>"$RECLAIM_ERR" >/dev/null; then
      echo "sweep: reclaimed orphaned stack set $ss ($region)"
    else
      echo "LEFTOVER: orphaned stack set $ss ($region) — could not delete: $(reclaim_err)"
    fi
  done
}

# Hook のフィクスチャは hook 型をアカウントに登録したまま残す（スタックを消しても型は残る）。
# deregister-type は "Third party types can't be deregistered" で拒否されるので deactivate-type を使う
# （2026-09-25 実測）。残すと翌月の登録が同名で衝突し、StackSet と同じ「別の理由で落ちる」に化ける。
sweep_hook_types() {
  local region=$1 t
  aws cloudformation list-types --region "$region" --type HOOK --visibility PRIVATE --no-paginate \
    --query "TypeSummaries[?contains(TypeName,'Cdkpf')].TypeName" --output text 2>/dev/null |
    tr '\t' '\n' | while read -r t; do
    [ -z "$t" ] || [ "$t" = "None" ] && continue
    if aws cloudformation deactivate-type --type HOOK --type-name "$t" --region "$region" \
         2>"$RECLAIM_ERR" >/dev/null; then
      echo "sweep: reclaimed orphaned hook type $t ($region)"
    else
      echo "LEFTOVER: orphaned hook type $t ($region) — could not delete: $(reclaim_err)"
    fi
  done
}

# AWS IoT の DomainConfiguration は名前がリージョン一意で、削除も 7 日待ち（reclaim を見よ）。
# CFN はスタック削除時にこれで転ぶので孤児が残り、翌月の再検証が同じ名前で
# ResourceAlreadyExists になる（#266 のスタックセット / フック型と同じ自家中毒）。
# verify-rule.sh は create-stack に --tags を渡さないのでタグ索引には載らない。名前で引く。
# AWS 組み込みの iot:Data-ATS / iot:Jobs / iot:CredentialProvider を消すとアカウントの
# データエンドポイントが死ぬので、cdkpf 接頭辞の絞り込みは外さないこと。
sweep_domain_configs() {
  local region=$1 arn
  aws iot list-domain-configurations --region "$region" \
    --query "domainConfigurations[?starts_with(domainConfigurationName,'cdkpf')].domainConfigurationArn" \
    --output text 2>/dev/null |
    tr '\t' '\n' | while read -r arn; do
    [ -z "$arn" ] || [ "$arn" = "None" ] && continue
    if reclaim "$arn" "$region"; then
      echo "sweep: reclaimed orphaned domain configuration $arn ($region)"
    else
      echo "LEFTOVER: orphaned domain configuration $arn ($region) — could not delete: $(reclaim_err)"
    fi
  done
}

# CloudFormation はスタックを消してもフィクスチャの S3 バケットを残す。CloudTrail は
# AWSLogs/<account>/CloudTrail/ に 0 バイトのマーカーを、AWS Config は ConfigWritabilityCheckFile を
# 書くので、スタック削除時の DeleteBucket が必ず「空でない」で失敗し、retain 削除で切り離される
# （2026-09-24 実測: #69 の実機ゲートで CloudTrail 33 個 / Config 32 個。月次でも同じだけ溜まる）。
# スタックタグは S3 に伝播していないのでタグ索引では拾えない。バケット名で拾う。
# 対象は cdkpf-pf-* だけ — ベンチのスタック名が cdkpf-<ルール id>-fail|pass で、ルール id は必ず
# pf- で始まるため。常設の cdkpf-bench-layers と cdkpf-<service>-probe-* には構造的に当たらない。
sweep_fixture_buckets() {
  local b region key vid
  aws s3api list-buckets --query "Buckets[?starts_with(Name,'cdkpf-pf-')].Name" --output text 2>/dev/null |
    tr '\t' '\n' | while read -r b; do
    { [ -z "$b" ] || [ "$b" = "None" ]; } && continue
    region=$(aws s3api get-bucket-location --bucket "$b" --query LocationConstraint --output text 2>/dev/null)
    { [ -z "$region" ] || [ "$region" = "None" ] || [ "$region" = "null" ]; } && region=us-east-1
    : > "$RECLAIM_ERR"
    # バージョンと削除マーカーが 1 つでも残っているとバケットは消せない
    aws s3api list-object-versions --bucket "$b" --region "$region" \
      --query '[Versions,DeleteMarkers][][].[Key,VersionId]' --output text 2>/dev/null |
      while read -r key vid; do
        [ -z "$key" ] && continue
        aws s3api delete-object --bucket "$b" --key "$key" --version-id "$vid" \
          --region "$region" >/dev/null 2>&1
      done
    if aws s3api delete-bucket --bucket "$b" --region "$region" 2>"$RECLAIM_ERR"; then
      echo "sweep: reclaimed fixture bucket $b ($region)"
    else
      echo "LEFTOVER: fixture bucket $b ($region) — could not delete: $(reclaim_err)"
    fi
  done
}

# OpenSearch Serverless の残骸を回収する。#268 のフィクスチャは CollectionGroup を実機に建てるので
# 課金物（コレクションもグループも、アイドルでも容量下限ぶん OCU が課金される）がスタック削除に
# 失敗したまま残り得るが、スタックタグは AOSS に伝播しないので上のタグ索引では拾えない。名前で引く。
# cdkpf- 接頭辞が付いているものだけ消す。接頭辞が無いものは消さずに LEFTOVER で報告する
# （#268 のフィクスチャは cdkpf- が付いているのが CollectionGroup 3 本だけで、Collection は probe-*、
#  ポリシーと SecurityConfig は enc-* / net-* / ap-* / lc-* / sc-*。消してよいと決められないので、
#  見えなくしないところまでやる。GA のカスタムルーティングと同じ扱い）。
# 引数: <region> <種別> <表示名> <接頭辞を判定する名前> <課金の注記> <削除コマンド...>
aoss_reclaim() {
  local region=$1 kind=$2 label=$3 name=$4 cost=$5; shift 5
  case "$name" in
    cdkpf-*) ;;
    *) echo "LEFTOVER: orphaned aoss $kind $label ($region$cost) — not a cdkpf- fixture, remove by hand"
       return 0 ;;
  esac
  : > "$RECLAIM_ERR"
  if "$@" >/dev/null 2>"$RECLAIM_ERR"; then
    echo "sweep: reclaimed orphaned aoss $kind $label ($region)"
  else
    echo "LEFTOVER: orphaned aoss $kind $label ($region$cost) — could not delete: $(reclaim_err)"
  fi
}

sweep_aoss() {
  local region=$1 id name lst del key t i spec
  # コレクションが先。1 枚でも残っているとグループの削除が拒否される
  aws opensearchserverless list-collections --region "$region" \
    --query 'collectionSummaries[].[id,name]' --output text 2>/dev/null |
    while IFS=$'\t' read -r id name; do
    { [ -z "$id" ] || [ "$id" = "None" ]; } && continue
    aoss_reclaim "$region" collection "$name ($id)" "$name" ', $0.5〜1/h' \
      aws opensearchserverless delete-collection --id "$id" --region "$region"
  done
  # 削除は非同期。消え終わるまで待たないとグループの削除が not empty で拒否される。
  # 待つのは cdkpf- のものだけ（報告しかしていない probe-* が残っていると毎月上限まで空回りする）
  for i in $(seq 30); do
    [ -z "$(aws opensearchserverless list-collections --region "$region" \
          --query "collectionSummaries[?starts_with(name,'cdkpf-')].id" --output text 2>/dev/null)" ] && break
    sleep 10
  done
  # グループは Generation と容量下限次第で課金が変わる。NEXTGEN + StandbyReplicas ENABLED の
  # min 0 なら空でアイドル $0 だが、下限を上げた形が残ると月 $350+ になる（#268 実測）
  aws opensearchserverless list-collection-groups --region "$region" \
    --query 'collectionGroupSummaries[].[id,name]' --output text 2>/dev/null |
    while IFS=$'\t' read -r id name; do
    { [ -z "$id" ] || [ "$id" = "None" ]; } && continue
    aoss_reclaim "$region" "collection group" "$name ($id)" "$name" ', 容量下限 > 0 なら $350+/月' \
      aws opensearchserverless delete-collection-group --id "$id" --region "$region"
  done
  # ここから下は $0。消し残しても課金しないが、翌月の同名フィクスチャが already exists で落ちて
  # 制約とは別の理由の失敗になる（#266 の StackSet / フック型と同じ自家中毒）。
  # 表は「list のサブコマンド : delete のサブコマンド : 出力のキー : --type」の順
  for spec in security-policies:security-policy:securityPolicySummaries:encryption \
              security-policies:security-policy:securityPolicySummaries:network \
              access-policies:access-policy:accessPolicySummaries:data \
              lifecycle-policies:lifecycle-policy:lifecyclePolicySummaries:retention; do
    IFS=: read -r lst del key t <<<"$spec"
    aws opensearchserverless "list-$lst" --type "$t" --region "$region" \
      --query "$key[].name" --output text 2>/dev/null |
      tr '\t' '\n' | while read -r name; do
      { [ -z "$name" ] || [ "$name" = "None" ]; } && continue
      aoss_reclaim "$region" "$t policy" "$name" "$name" '' \
        aws opensearchserverless "delete-$del" --type "$t" --name "$name" --region "$region"
    done
  done
  # SecurityConfig は summaries に name が無く、id が <type>/<account>/<name>（saml 以外も同じ形。
  # #268 実測）。接頭辞は最後のセグメントで判定する。--type は必須なので enum を回す
  for t in saml iamidentitycenter iamfederation; do
    aws opensearchserverless list-security-configs --type "$t" --region "$region" \
      --query 'securityConfigSummaries[].id' --output text 2>/dev/null |
      tr '\t' '\n' | while read -r id; do
      { [ -z "$id" ] || [ "$id" = "None" ]; } && continue
      aoss_reclaim "$region" "$t security config" "$id" "${id##*/}" '' \
        aws opensearchserverless delete-security-config --id "$id" --region "$region"
    done
  done
  # VPC エンドポイントはフィクスチャで使っていないが、出たときに見えるようにしておく
  aws opensearchserverless list-vpc-endpoints --region "$region" \
    --query 'vpcEndpointSummaries[].[id,name]' --output text 2>/dev/null |
    while IFS=$'\t' read -r id name; do
    { [ -z "$id" ] || [ "$id" = "None" ]; } && continue
    aoss_reclaim "$region" "vpc endpoint" "$name ($id)" "$name" '' \
      aws opensearchserverless delete-vpc-endpoint --id "$id" --region "$region"
  done
}

# us-west-2 は Global Accelerator のフィクスチャ用（GA は us-west-2 にしか作れない）
for region in ap-northeast-1 us-east-1 us-west-2; do
  aws cloudformation list-stacks --region "$region" \
    --query "StackSummaries[?starts_with(StackName,'cdkpf-') && StackStatus!='DELETE_COMPLETE'].StackName" \
    --output text | tr '\t' '\n' | while read -r s; do
    [ -z "$s" ] || [ "$s" = "None" ] && continue
    echo "sweep: deleting $s ($region)"
    aws cloudformation delete-stack --stack-name "$s" --region "$region" 2>/dev/null
    if ! aws cloudformation wait stack-delete-complete --stack-name "$s" --region "$region" 2>/dev/null; then
      ids=$(aws cloudformation describe-stack-resources --stack-name "$s" --region "$region" \
        --query "StackResources[?ResourceStatus=='DELETE_FAILED'].LogicalResourceId" --output text 2>/dev/null)
      if [ -n "$ids" ] && [ "$ids" != "None" ]; then
        aws cloudformation delete-stack --stack-name "$s" --region "$region" --retain-resources $ids 2>/dev/null
        if aws cloudformation wait stack-delete-complete --stack-name "$s" --region "$region" 2>/dev/null; then
          echo "LEFTOVER: $s ($region) deleted with retained resources: $ids"
        else
          echo "LEFTOVER: $s ($region) still stuck after retain-delete: $ids"
        fi
      else
        echo "LEFTOVER: $s ($region) delete did not complete"
      fi
    fi
  done

  # retain 削除で切り離されたリソースはスタックが消えているので list-stacks では拾えない。
  # スタックタグ cdkpf は課金対象リソースに伝播しているので、タグから直接残骸を探して消す。
  aws resourcegroupstaggingapi get-resources --region "$region" --tag-filters Key=cdkpf \
    --query 'ResourceTagMappingList[].ResourceARN' --output text 2>/dev/null |
    tr '\t' '\n' | while read -r arn; do
    [ -z "$arn" ] || [ "$arn" = "None" ] && continue
    if reclaim "$arn" "$region"; then
      echo "sweep: reclaimed orphaned resource $arn ($region)"
    else
      echo "LEFTOVER: orphaned resource $arn ($region) — could not delete: $(reclaim_err)"
    fi
  done

  sweep_dns_firewall "$region"
  sweep_stack_sets "$region"
  sweep_hook_types "$region"
  sweep_domain_configs "$region"
  sweep_aoss "$region"
done

sweep_fixture_buckets
sweep_global_accelerator
echo "sweep done"
