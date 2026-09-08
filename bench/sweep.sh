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
  local arn=$1 region=$2 svc res name pool domain
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
      # 削除保護とカスタムドメインはどちらも DeleteUserPool を拒否する。順に外してから消す。
      # update-user-pool は指定しなかった設定を既定値に戻すが、消す直前のプールなので影響しない
      pool=${res#*/}
      aws cognito-idp update-user-pool --user-pool-id "$pool" --region "$region" \
        --deletion-protection INACTIVE >/dev/null
      domain=$(aws cognito-idp describe-user-pool --user-pool-id "$pool" --region "$region" \
        --query UserPool.Domain --output text)
      if [ -n "$domain" ] && [ "$domain" != None ]; then
        aws cognito-idp delete-user-pool-domain --user-pool-id "$pool" --domain "$domain" \
          --region "$region" >/dev/null
      fi
      aws cognito-idp delete-user-pool --user-pool-id "$pool" --region "$region" >/dev/null ;;
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
  esac 2>"$RECLAIM_ERR"
}

# 失敗理由を 1 行に畳んで返す。取れなかったら手作業を促す既定文
reclaim_err() {
  local msg
  msg=$(tr -s '\n\t' '  ' < "$RECLAIM_ERR" | head -c 300)
  echo "${msg:-remove by hand}"
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
done
echo "sweep done"
