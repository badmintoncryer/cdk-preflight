package cdk_preflight

import rego.v1

_pf_lcsar_fix := "Reference a code signing config in the same region and account as the function"

_pf_lcsar_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"

violation contains make_diag_full("pf-lambda-code-signing-arn-region", "ERROR", name,
	"Properties.CodeSigningConfigArn",
	sprintf("code signing config region '%v' is not the deploy region '%v'; a function can only reference a config from its own region", [parts[3], region]),
	_pf_lcsar_fix, _pf_lcsar_url) if {
	region := data.cdk_preflight.deploy_region
	some name in _pf_lam_fn
	parts := _pf_lam_arn(resolve(name, "Properties.CodeSigningConfigArn"))
	parts[3] != region
}
