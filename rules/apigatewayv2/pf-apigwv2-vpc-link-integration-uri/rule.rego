package cdk_preflight

import rego.v1

# The ARN has to name a listener, not the load balancer itself.
violation contains make_diag_full("pf-apigwv2-vpc-link-integration-uri", "ERROR", name,
	"Properties.IntegrationUri",
	sprintf("IntegrationUri '%s' is a load balancer ARN, not a listener ARN; the integration create fails with \"For VpcLink VPC_LINK, integration uri should be a valid ELB listener ARN or a valid Cloud Map service ARN.\"", [uri]),
	"Point IntegrationUri at the listener ARN (ELB) or a Cloud Map service ARN",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-integration.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Integration")
	resolve(name, "Properties.ConnectionType") == "VPC_LINK"
	uri := resolve(name, "Properties.IntegrationUri")
	is_string(uri)
	startswith(uri, "arn:")
	parts := split(uri, ":")
	count(parts) >= 6
	parts[2] == "elasticloadbalancing"
	startswith(parts[5], "loadbalancer/")
}
