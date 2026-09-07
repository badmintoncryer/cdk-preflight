package cdk_preflight

import rego.v1

_pf_luae_fix := "Set AuthType to AWS_IAM or NONE"

_pf_luae_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-url.html"

violation contains make_diag_full("pf-lambda-url-auth-type-enum", "ERROR", name,
	"Properties.AuthType",
	sprintf("AuthType '%v'; a function URL is either IAM-signed (AWS_IAM) or public (NONE)", [v]),
	_pf_luae_fix, _pf_luae_url) if {
	some name in _pf_lam_url
	v := resolve(name, "Properties.AuthType")
	is_string(v)
	not v in {"AWS_IAM", "NONE"}
}
