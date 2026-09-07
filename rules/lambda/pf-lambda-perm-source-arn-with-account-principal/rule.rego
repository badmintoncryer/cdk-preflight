package cdk_preflight

import rego.v1

_pf_lpap_fix := "Drop SourceArn when the principal is an account or IAM ARN"

_pf_lpap_url := "https://docs.aws.amazon.com/lambda/latest/api/API_AddPermission.html"

violation contains make_diag_full("pf-lambda-perm-source-arn-with-account-principal", "ERROR", name,
	"Properties.SourceArn",
	sprintf("SourceArn with principal '%v'; aws:SourceArn is set by a calling service, so an IAM principal calling directly never matches it", [p]),
	_pf_lpap_fix, _pf_lpap_url) if {
	some name in _pf_lam_perm
	props := _pf_lam_props(name)
	_pf_lam_has_key(props, "SourceArn")
	p := resolve(name, "Properties.Principal")
	is_string(p)
	startswith(p, "arn:")
}
