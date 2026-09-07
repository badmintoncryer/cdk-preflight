package cdk_preflight

import rego.v1

_pf_lppd_fix := "Use the domain form of the service principal (s3.amazonaws.com, not s3)"

_pf_lppd_url := "https://docs.aws.amazon.com/lambda/latest/api/API_AddPermission.html"

violation contains make_diag_full("pf-lambda-perm-principal-service-domain", "ERROR", name,
	"Properties.Principal",
	sprintf("principal '%v' is neither an account, an ARN nor a domain-style service identifier; services are named like s3.amazonaws.com", [v]),
	_pf_lppd_fix, _pf_lppd_url) if {
	some name in _pf_lam_perm
	v := resolve(name, "Properties.Principal")
	is_string(v)
	v != "*"
	not contains(v, ".")
	not startswith(v, "arn:")
	not regex.match(`^[0-9]{12}$`, v)
}
