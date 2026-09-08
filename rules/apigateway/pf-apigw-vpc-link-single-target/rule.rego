package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigw-vpc-link-single-target", "ERROR", name,
	"Properties.TargetArns",
	sprintf("TargetArns lists %d load balancers; the VPC link create fails with \"More than one target arn specified for vpc link.\"", [count(t)]),
	"List exactly one Network Load Balancer ARN",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-vpclink.html") if {
	some name in resources_of_type("AWS::ApiGateway::VpcLink")
	t := flatten_list(name, "Properties.TargetArns")
	count(t) > 1
}
