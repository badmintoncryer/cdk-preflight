package cdk_preflight

import rego.v1

_pf_ec2hrg_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-instance.html"

_pf_ec2hrg_tenancy(name) := t if {
	t := resolve(name, "Properties.Tenancy")
	is_string(t)
}

_pf_ec2hrg_tenancy(name) := "default" if _pf_ec2lib_absent(name, "Tenancy")

violation contains make_diag_full("pf-ec2-host-resource-group-tenancy", "ERROR", name,
	"Properties.Tenancy",
	sprintf("HostResourceGroupArn is set but Tenancy is '%s' (\"When HostResourceGroupArn is specified, tenancy must be set to 'host'\")", [t]),
	"Set Tenancy to host",
	_pf_ec2hrg_url) if {
	some name in resources_of_type("AWS::EC2::Instance")
	not _pf_ec2lib_absent(name, "HostResourceGroupArn")
	t := _pf_ec2hrg_tenancy(name)
	t != "host"
}
