package cdk_preflight

import rego.v1

# デフォルトクォータは 10 だが引き上げ可能（最大 20）なので、静的に確実なのは
# ハード上限 20 の超過のみ（bench アカウントも 20 に引き上げ済みで 11 個は成功する）。
# 10 超はアカウント設定次第で成功し得るため ERROR にしない。
violation contains make_diag_full("pf-iam-managed-policy-count", "ERROR", name,
	"Properties.ManagedPolicyArns",
	sprintf("%d managed policies are attached, but IAM allows at most 20 per role/user/group (hard maximum; the default quota is 10); deployment fails with LimitExceeded", [n]),
	"Consolidate statements into fewer managed policies",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html") if {
	some rtype in {"AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"}
	some name in resources_of_type(rtype)
	arr := resolve(name, "Properties.ManagedPolicyArns")
	is_array(arr)
	n := count(arr)
	n > 20
}
