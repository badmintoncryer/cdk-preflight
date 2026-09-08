package cdk_preflight

import rego.v1

_pf_agvivlc_missing(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "ConnectionId", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-apigwv2-integration-vpc-link-connection-id", "ERROR", name,
	"Properties.ConnectionId",
	"ConnectionType is VPC_LINK but ConnectionId is not set; the integration create fails with \"ConnectionId must be set to vpcLinkId for ConnectionType VPC_LINK\"",
	"Set ConnectionId to the VpcLink id",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-integration.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Integration")
	resolve(name, "Properties.ConnectionType") == "VPC_LINK"
	_pf_agvivlc_missing(name)
}
