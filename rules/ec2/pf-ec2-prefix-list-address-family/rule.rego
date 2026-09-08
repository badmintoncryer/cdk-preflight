package cdk_preflight

import rego.v1

_pf_ec2plaf_bad("IPv4", cidr) if contains(cidr, ":")

_pf_ec2plaf_bad("IPv6", cidr) if not contains(cidr, ":")

violation contains make_diag_full("pf-ec2-prefix-list-address-family", "ERROR", name,
	sprintf("Properties.Entries.%d.Cidr", [e.index]),
	sprintf("An %s prefix list cannot hold the CIDR '%s' (\"An (%s) prefix list cannot contain an (%s) CIDR.\")", [fam, cidr, fam, cidr]),
	"Match the entry CIDRs to AddressFamily, or split them into one list per family",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-prefixlist.html") if {
	some name in resources_of_type("AWS::EC2::PrefixList")
	fam := resolve(name, "Properties.AddressFamily")
	some e in flatten_list(name, "Properties.Entries")
	cidr := object.get(e.value, "Cidr", "")
	is_string(cidr)
	_pf_ec2plaf_bad(fam, cidr)
}
