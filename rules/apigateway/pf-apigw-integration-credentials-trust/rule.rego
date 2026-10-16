package cdk_preflight

import rego.v1

# The role in Integration.Credentials is assumed by API Gateway on each request,
# and PutIntegration does not check that it can be. A role whose trust policy
# does not name apigateway.amazonaws.com deploys and then every request returns
# 500 ("API Gateway does not have permission to assume the provided role").
violation contains make_diag_full("pf-apigw-integration-credentials-trust", "ERROR", name,
	"Properties.Integration.Credentials",
	sprintf("Integration.Credentials is role '%s', whose trust policy does not let apigateway.amazonaws.com assume it; every request to this method returns 500", [role]),
	sprintf("Add apigateway.amazonaws.com to the Service principals of %s's AssumeRolePolicyDocument", [role]),
	"https://docs.aws.amazon.com/apigateway/latest/developerguide/integration-request-basic-setup.html") if {
	some name in resources_of_type("AWS::ApiGateway::Method")
	props := input.resources[name].properties
	is_object(props)
	integ := object.get(props, "Integration", null)
	is_object(integ)
	role := _pf_iamlib_role_without_service(object.get(integ, "Credentials", null), "apigateway.amazonaws.com")
}
