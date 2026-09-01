package cdk_preflight

import rego.v1

# ハード上限（Service Quotas の「Maximum quota」= それ以上引き上げ不可能な値）:
#   role 25 / user 20 / group 10（group は adjustable: false、実測でも確認）。
# デフォルト（role 20 / user 10 / group 10）超はアカウントのクォータ引き上げ次第で
# 成功し得るため ERROR にしない（bench アカウントの role=20 で 11 個成功を実測済み）。
_pf_iampol_limits := {
	"AWS::IAM::Role": 25,
	"AWS::IAM::User": 20,
	"AWS::IAM::Group": 10,
}

violation contains make_diag_full("pf-iam-managed-policy-count", "ERROR", name,
	"Properties.ManagedPolicyArns",
	sprintf("%d managed policies are attached, but the hard maximum for %s is %d (quota defaults: role 20, user 10, group 10; raisable only up to the hard maximum); deployment fails with LimitExceeded", [n, rtype, limit]),
	"Consolidate statements into fewer managed policies",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html") if {
	some rtype, limit in _pf_iampol_limits
	some name in resources_of_type(rtype)
	arr := resolve(name, "Properties.ManagedPolicyArns")
	is_array(arr)
	n := count(arr)
	n > limit
}
