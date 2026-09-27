#!/bin/bash
# フィクスチャが前提にする常設物を、今の認証情報のアカウントにそろえる。冪等。
# bench (214794239830) と月次の検証アカウント (502761806921) に同じ名前で置き、フィクスチャは
# ${AWS::AccountId} と {{resolve:ssm:/cdkpf/fixtures/...}} で自アカウントのものを指す。別アカウントの
# ものを指すと、制約より先にクロスアカウントのアクセスで倒れて見分けが付かない（#284）。
# 月次アカウントには手元から書けないので、monthly-verify の fixtures ジョブが毎回これを流す。
# 置き場所は全部 us-east-1（常設物を指すフィクスチャはどれも us-east-1 で走る）。
set -euo pipefail
cd "$(dirname "$0")"
R=us-east-1
A=$(aws sts get-caller-identity --query Account --output text)
put() { aws ssm put-parameter --region $R --name "$1" --value "$2" --type String --overwrite >/dev/null; }

# S3: 中身は bench/fixtures/。名前を cdkpf-pf- で始めないこと（sweep.sh がフィクスチャの消し残りとして消す）。
# バージョニングとポリシーは REFERENCE モードのレイヤー用: S3ObjectVersion で版を指し、lambda.amazonaws.com
# 自身がオブジェクトを読む。版 ID はアカウントごとに違うので SSM に置く
B="cdkpf-fixtures-$A"
aws s3api head-bucket --bucket "$B" --region $R >/dev/null 2>&1 ||
  aws s3api create-bucket --bucket "$B" --region $R >/dev/null
aws s3api put-bucket-versioning --bucket "$B" --region $R --versioning-configuration Status=Enabled
aws s3api put-bucket-policy --bucket "$B" --region $R --policy "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"lambda\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":[\"s3:GetObject\",\"s3:GetObjectVersion\"],\"Resource\":\"arn:aws:s3:::$B/*\"}]}"
aws s3 sync fixtures "s3://$B" --region $R --only-show-errors
put /cdkpf/fixtures/s3/l.zip-version \
  "$(aws s3api head-object --bucket "$B" --key l.zip --region $R --query VersionId --output text)"

# 宣言できるもの（IAM ロール、SNS、ECR リポジトリ、Glue ジョブ）。スタック名を cdkpf- で始めないこと
# （sweep.sh が消す）。初回の作成が倒れると ROLLBACK_COMPLETE のまま更新できないので、消して作り直す
S=preflight-fixtures
if [ "$(aws cloudformation describe-stacks --stack-name $S --region $R \
      --query 'Stacks[0].StackStatus' --output text 2>/dev/null)" = ROLLBACK_COMPLETE ]; then
  aws cloudformation delete-stack --stack-name $S --region $R
  aws cloudformation wait stack-delete-complete --stack-name $S --region $R
fi
aws cloudformation deploy --stack-name $S --region $R --template-file fixtures.template.json \
  --capabilities CAPABILITY_NAMED_IAM --no-fail-on-empty-changeset

# ACM: ARN はアカウントごとに違う UUID を含むので SSM に置く（検証待ちのあいだも置く）。検証の CNAME は
# bench の appnao.com ゾーンにしか置けない（他のアカウントにはゾーンが無い）ので、ここでは出力するだけ。
# 検証待ちと出たら bench でそのレコードを足すこと
cert() { # <domain> <SSM の名前>
  local arn
  arn=$(aws acm list-certificates --region $R --certificate-statuses PENDING_VALIDATION ISSUED \
    --query "CertificateSummaryList[?DomainName=='$1'].CertificateArn | [0]" --output text)
  if [ "$arn" = None ]; then
    arn=$(aws acm request-certificate --region $R --domain-name "$1" --validation-method DNS \
      --query CertificateArn --output text)
    sleep 10 # 検証レコードが載るまで数秒かかる
  fi
  put "$2" "$arn"
  aws acm describe-certificate --region $R --certificate-arn "$arn" --output text --query \
    'Certificate.[DomainName, Status, DomainValidationOptions[0].ResourceRecord.Name, DomainValidationOptions[0].ResourceRecord.Value]'
}
cert '*.appnao.com' /cdkpf/fixtures/acm/wildcard-appnao-com
cert cdkpf.appnao.com /cdkpf/fixtures/acm/cdkpf-appnao-com

# 既定 VPC: bench の既定 VPC を直書きしたフィクスチャは、verify-rule.sh がここの ID に読み替える
[ "$(aws ec2 describe-vpcs --region $R --filters Name=is-default,Values=true \
    --query 'Vpcs[0].VpcId' --output text)" != None ] ||
  aws ec2 create-default-vpc --region $R >/dev/null

# CodeCommit は新規の顧客を締め出していて、アカウントによっては作れない。スタックに入れると
# それだけで全部が巻き戻るので外に置き、落ちても先へ進む
aws codecommit get-repository --repository-name cdkpf-probe --region $R >/dev/null 2>&1 ||
  aws codecommit create-repository --repository-name cdkpf-probe --region $R >/dev/null ||
  echo "!! codecommit: cannot create cdkpf-probe in $A — the fixtures that clone it will be INCONCLUSIVE"

# ECR のイメージ: PackageType: Image の関数は作成時にイメージを実際に引くので、自アカウントの
# プライベート ECR に実物が要る（public.ecr.aws を直接指すのは pf-lambda-image-uri-private-ecr の違反そのもの）
if ! aws ecr describe-images --repository-name cdkpf-bench-image --image-ids imageTag=py313 \
     --region $R >/dev/null 2>&1; then
  I="$A.dkr.ecr.$R.amazonaws.com/cdkpf-bench-image:py313"
  aws ecr get-login-password --region $R | docker login --username AWS --password-stdin "${I%%/*}"
  docker pull --platform linux/amd64 public.ecr.aws/lambda/python:3.13
  docker tag public.ecr.aws/lambda/python:3.13 "$I"
  docker push "$I"
fi
