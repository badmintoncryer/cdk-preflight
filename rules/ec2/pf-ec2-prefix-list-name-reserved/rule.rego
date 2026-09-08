package cdk_preflight

import rego.v1

_pf_ec2pln_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-prefixlist.html"

_pf_ec2pln_reserved := ["com.amazonaws.", "com.amazon.", "com.aws."]

violation contains make_diag_full("pf-ec2-prefix-list-name-reserved", "ERROR", name,
	"Properties.PrefixListName",
	sprintf("PrefixListName starts with the reserved prefix '%s' (\"The prefix list name cannot begin with (com.amazonaws., com.amazon., com.aws.).\")", [p]),
	"Pick a name that does not start with com.amazonaws., com.amazon. or com.aws.",
	_pf_ec2pln_url) if {
	some name in resources_of_type("AWS::EC2::PrefixList")
	n := resolve(name, "Properties.PrefixListName")
	is_string(n)
	some p in _pf_ec2pln_reserved
	startswith(n, p)
}
