package cdk_preflight

import rego.v1

_pf_ec2eh_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-instance.html"

violation contains make_diag_full("pf-ec2-enclave-hibernation-exclusive", "ERROR", name,
	"Properties.EnclaveOptions",
	"EnclaveOptions and HibernationOptions are both enabled (\"You cannot enable Nitro Enclaves and hibernation on the same instance.\")",
	"Enable one of the two",
	_pf_ec2eh_url) if {
	some name in resources_of_type("AWS::EC2::Instance")
	coerce_to_bool(resolve(name, "Properties.EnclaveOptions.Enabled")) == true
	coerce_to_bool(resolve(name, "Properties.HibernationOptions.Configured")) == true
}
