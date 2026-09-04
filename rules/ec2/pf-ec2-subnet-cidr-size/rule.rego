package cdk_preflight

import rego.v1

_pf_subnetcidr_len(c) := to_number(parts[1]) if {
	parts := split(c, "/")
	count(parts) == 2
}

violation contains make_diag_full("pf-ec2-subnet-cidr-size", "ERROR", name,
	"Properties.CidrBlock",
	sprintf("Subnet CIDR '%s' has a /%d netmask; EC2 accepts /16 through /28 and rejects the create call otherwise", [c, n]),
	"Resize the subnet CIDR to a netmask between /16 and /28",
	"https://docs.aws.amazon.com/vpc/latest/userguide/subnet-sizing.html") if {
	some name in resources_of_type("AWS::EC2::Subnet")
	c := resolve(name, "Properties.CidrBlock")
	is_string(c)
	n := _pf_subnetcidr_len(c)
	_pf_subnetcidr_out(n)
}

_pf_subnetcidr_out(n) if n < 16

_pf_subnetcidr_out(n) if n > 28
