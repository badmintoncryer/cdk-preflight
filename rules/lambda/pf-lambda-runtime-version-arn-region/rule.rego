package cdk_preflight

import rego.v1

_pf_lrvr_fix := "Build the ARN with ${AWS::Region} (arn:${AWS::Partition}:lambda:${AWS::Region}::runtime:<id>)"

_pf_lrvr_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-function-runtimemanagementconfig.html"

violation contains make_diag_full("pf-lambda-runtime-version-arn-region", "ERROR", name,
	"Properties.RuntimeManagementConfig.RuntimeVersionArn",
	sprintf("runtime version ARN names region '%v' but the function deploys to '%v'; runtime versions are resolved in the function's own region", [parts[3], region]),
	_pf_lrvr_fix, _pf_lrvr_url) if {
	region := data.cdk_preflight.deploy_region
	some name in _pf_lam_fn
	rmc := _pf_lam_obj(_pf_lam_props(name), "RuntimeManagementConfig")
	parts := _pf_lam_arn(object.get(rmc, "RuntimeVersionArn", ""))
	parts[2] == "lambda"
	parts[3] != region
}
