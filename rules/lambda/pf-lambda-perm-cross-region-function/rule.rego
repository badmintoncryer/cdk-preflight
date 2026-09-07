package cdk_preflight

import rego.v1

_pf_lpcr_fix := "Declare the permission in the same region as the function"

_pf_lpcr_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html"

violation contains make_diag_full("pf-lambda-perm-cross-region-function", "ERROR", name,
	"Properties.FunctionName",
	sprintf("function region '%v' is not the deploy region '%v'; a resource policy is attached in the function's own region and cannot be added across regions", [parts[3], region]),
	_pf_lpcr_fix, _pf_lpcr_url) if {
	region := data.cdk_preflight.deploy_region
	some name in _pf_lam_perm
	parts := _pf_lam_arn(resolve(name, "Properties.FunctionName"))
	parts[2] == "lambda"
	parts[3] != region
}
