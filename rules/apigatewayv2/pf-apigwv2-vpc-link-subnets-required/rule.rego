package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigwv2-vpc-link-subnets-required", "ERROR", name,
	"Properties.SubnetIds",
	"SubnetIds is empty; the VPC link create fails with \"SubnetIds for a vpc link cannot be empty\"",
	"List at least one subnet the VPC link places its network interfaces in",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-vpclink.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::VpcLink")
	count(flatten_list(name, "Properties.SubnetIds")) == 0
}
