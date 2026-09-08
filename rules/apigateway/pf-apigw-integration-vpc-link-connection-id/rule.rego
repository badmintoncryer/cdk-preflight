package cdk_preflight

import rego.v1

# Absence is proven against the preprocessed document (see AGENTS.md).
_pf_apgivlc_missing(name) if {
	props := input.resources[name].properties
	is_object(props)
	integ := object.get(props, "Integration", {})
	is_object(integ)
	object.get(integ, "ConnectionId", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-apigw-integration-vpc-link-connection-id", "ERROR", name,
	"Properties.Integration.ConnectionId",
	"Integration.ConnectionType is VPC_LINK but ConnectionId is not set; the method create fails with \"ConnectionId should be set to the vpcLinkId or stage variable on connection type VPC_LINK\"",
	"Set Integration.ConnectionId to the VpcLink id (or a stage variable)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-method-integration.html") if {
	some name in resources_of_type("AWS::ApiGateway::Method")
	resolve(name, "Properties.Integration.ConnectionType") == "VPC_LINK"
	_pf_apgivlc_missing(name)
}
