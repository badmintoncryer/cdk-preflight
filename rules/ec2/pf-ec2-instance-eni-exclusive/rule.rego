package cdk_preflight

import rego.v1

_pf_ec2ie_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-instance.html"

violation contains make_diag_full("pf-ec2-instance-eni-exclusive", "ERROR", name,
	"Properties.SecurityGroupIds",
	"NetworkInterfaces and instance-level SecurityGroupIds cannot both be set (\"Network interfaces and an instance-level security groups may not be specified on the same request\")",
	"Move the security groups into the NetworkInterfaces entry as GroupSet",
	_pf_ec2ie_url) if {
	some name in resources_of_type("AWS::EC2::Instance")
	count(flatten_list(name, "Properties.NetworkInterfaces")) > 0
	count(flatten_list(name, "Properties.SecurityGroupIds")) > 0
}
