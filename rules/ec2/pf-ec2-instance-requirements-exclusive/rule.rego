package cdk_preflight

import rego.v1

_pf_ec2ir_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-launchtemplate.html"

violation contains make_diag_full("pf-ec2-instance-requirements-exclusive", "ERROR", name,
	"Properties.LaunchTemplateData.InstanceType",
	"LaunchTemplateData sets both InstanceType and InstanceRequirements (\"Either the instance type or the instance requirements can be specified in the request, but not both\")",
	"Keep one of the two",
	_pf_ec2ir_url) if {
	some name in resources_of_type("AWS::EC2::LaunchTemplate")
	not _pf_ec2lib_absent_at(name, ["LaunchTemplateData", "InstanceType"])
	not _pf_ec2lib_absent_at(name, ["LaunchTemplateData", "InstanceRequirements"])
}
