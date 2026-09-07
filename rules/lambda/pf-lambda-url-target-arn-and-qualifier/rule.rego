package cdk_preflight

import rego.v1

_pf_luta_fix := "Drop Qualifier when TargetFunctionArn already carries the alias"

_pf_luta_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-url.html"

violation contains make_diag_full("pf-lambda-url-target-arn-and-qualifier", "ERROR", name,
	"Properties.Qualifier",
	"a qualifier in both TargetFunctionArn and Qualifier; the two are alternative ways to name the same alias and the pair is not defined",
	_pf_luta_fix, _pf_luta_url) if {
	some name in _pf_lam_url
	props := _pf_lam_props(name)
	_pf_lam_has_key(props, "Qualifier")
	parts := _pf_lam_arn(resolve(name, "Properties.TargetFunctionArn"))
	parts[2] == "lambda"
	count(parts) > 7
}
