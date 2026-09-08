package cdk_preflight

import rego.v1

_pf_ec2cs_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-instance.html"

violation contains make_diag_full("pf-ec2-credit-specification-burstable", "ERROR", name,
	"Properties.CreditSpecification",
	sprintf("CreditSpecification is set on '%s', which is not a burstable (T family) type", [it]),
	"Remove CreditSpecification, or switch to a t2/t3/t3a/t4g instance type",
	_pf_ec2cs_url) if {
	some name in resources_of_type("AWS::EC2::Instance")
	not _pf_ec2lib_absent(name, "CreditSpecification")
	it := resolve(name, "Properties.InstanceType")
	is_string(it)
	not regex.match(`^t[0-9]`, it)
}
