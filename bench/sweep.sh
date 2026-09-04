#!/bin/bash
# cdkpf-* 残存スタックの全掃除。DELETE_FAILED は retain 削除まで自動で撃ち、
# 回収しきれなかったものは "LEFTOVER:" 行で報告する（report.sh が拾う）。
set -u
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
done
echo "sweep done"
