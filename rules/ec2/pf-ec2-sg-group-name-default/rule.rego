package cdk_preflight

import rego.v1

_pf_ec2sgn_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-securitygroup.html"

violation contains make_diag_full("pf-ec2-sg-group-name-default", "ERROR", name,
	"Properties.GroupName",
	"GroupName 'default' is reserved for the VPC default security group (\"Cannot use reserved security group name: default\")",
	"Pick another name, or drop GroupName and let CloudFormation generate one",
	_pf_ec2sgn_url) if {
	some name in resources_of_type("AWS::EC2::SecurityGroup")
	resolve(name, "Properties.GroupName") == "default"
}
