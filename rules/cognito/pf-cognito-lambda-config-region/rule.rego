package cdk_preflight

import rego.v1

# Cross-account triggers are accepted; only the region has to match
# (measured 2026-09-08). data.cdk_preflight.deploy_region is injected only in
# enforce mode with a concrete region.

_pf_cglcr_arn(v) := v if is_string(v)

_pf_cglcr_arn(v) := a if {
	is_object(v)
	a := object.get(v, "LambdaArn", "__pf_absent")
	is_string(a)
}

violation contains make_diag_full("pf-cognito-lambda-config-region", "ERROR", name,
	sprintf("Properties.LambdaConfig.%s", [k]),
	sprintf("the %v trigger is in '%v' but the pool deploys to '%v'; the pool create fails with \"Cross-region lambda functions are not supported\"", [k, r, region]),
	"Point the trigger at a function in the pool's own region",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	lc := _pf_coglib_g1(name, "LambdaConfig")
	is_object(lc)
	some k, v in lc
	arn := _pf_cglcr_arn(v)
	_pf_coglib_arn_service(arn) == "lambda"
	r := _pf_coglib_arn_region(arn)
	r != region
}
