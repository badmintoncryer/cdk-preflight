package cdk_preflight

import rego.v1

_pf_lcpr_fix := "Build the ARN with ${AWS::Region} and ${AWS::AccountId}"

_pf_lcpr_url := "https://docs.aws.amazon.com/lambda/latest/api/API_LambdaManagedInstancesCapacityProviderConfig.html"

violation contains make_diag_full("pf-lambda-capacity-provider-arn-region", "ERROR", name,
	"Properties.CapacityProviderConfig.LambdaManagedInstancesCapacityProviderConfig.CapacityProviderArn",
	sprintf("capacity provider region '%v' is not the deploy region '%v'; a function draws managed instances from a provider in its own region", [parts[3], region]),
	_pf_lcpr_fix, _pf_lcpr_url) if {
	region := data.cdk_preflight.deploy_region
	some name in _pf_lam_fn
	cpc := _pf_lam_obj(_pf_lam_props(name), "CapacityProviderConfig")
	lmi := _pf_lam_obj(cpc, "LambdaManagedInstancesCapacityProviderConfig")
	parts := _pf_lam_arn(object.get(lmi, "CapacityProviderArn", ""))
	parts[2] == "lambda"
	parts[3] != region
}
