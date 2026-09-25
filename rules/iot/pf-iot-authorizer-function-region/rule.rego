package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-authorizer-function-region", "ERROR", name,
	"Properties.AuthorizerFunctionArn",
	sprintf("the authorizer's Lambda is in '%s' but the authorizer deploys to '%s'; CreateAuthorizer answers \"Lambda function region must be same as authorizer <name> region\"", [fnRegion, region]),
	"Point AuthorizerFunctionArn at a function in the authorizer's own region",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_CreateAuthorizer.html") if {
	some name in resources_of_type("AWS::IoT::Authorizer")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	fnRegion := _pf_iotlib_arn_region(resolve(name, "Properties.AuthorizerFunctionArn"), "lambda")
	fnRegion != region
}
