#!/bin/bash
# テンプレートの中に書けない常設物（入れ子スタックの子テンプレートなど）を、今の認証情報の
# アカウントの cdkpf-fixtures-<account> に bench/fixtures/ から同期する。冪等。
# フィクスチャは {"Fn::Sub": "...cdkpf-fixtures-${AWS::AccountId}..."} で自アカウントのものを指す。
# 月次の検証アカウント (502761806921) には手元から書けないので、verify-all.sh が毎回これを流す（#284）。
# 名前を cdkpf-pf- で始めないこと: sweep.sh がフィクスチャの消し残りとして消す。
set -euo pipefail
cd "$(dirname "$0")"
B="cdkpf-fixtures-$(aws sts get-caller-identity --query Account --output text)"
# us-east-1 は持ち主の作り直しに 200 を返すので、並列のシャードが同時に作っても壊れない
aws s3api head-bucket --bucket "$B" --region us-east-1 >/dev/null 2>&1 ||
  aws s3api create-bucket --bucket "$B" --region us-east-1 >/dev/null
aws s3 sync fixtures "s3://$B" --region us-east-1 --only-show-errors
