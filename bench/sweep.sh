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
    *) return 1 ;;
  esac 2>"$RECLAIM_ERR" && return 0
  # タグ索引には既に消えたリソースの行が残ることがある（Cognito のプールは削除後も、
  # ECS のクラスタは INACTIVE のまま返る）。存在しないものは回収済みとして扱う
  grep -qE 'NotFoundException|does not exist' "$RECLAIM_ERR"
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

for region in ap-northeast-1 us-east-1; do
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
done
echo "sweep done"
