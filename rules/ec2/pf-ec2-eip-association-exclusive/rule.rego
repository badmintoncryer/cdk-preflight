package cdk_preflight

import rego.v1

_pf_ec2eipa_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-eipassociation.html"

violation contains make_diag_full("pf-ec2-eip-association-exclusive", "ERROR", name,
	"Properties.EIP",
	"AllocationId and EIP cannot both be set (\"You may specify public IP or allocation id, but not both in the same call\")",
	"Keep AllocationId for a VPC address",
	_pf_ec2eipa_url) if {
	some name in resources_of_type("AWS::EC2::EIPAssociation")
	not _pf_ec2lib_absent(name, "AllocationId")
	not _pf_ec2lib_absent(name, "EIP")
}
