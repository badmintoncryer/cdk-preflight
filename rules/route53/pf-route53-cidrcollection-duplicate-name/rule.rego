package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-cidrcollection-duplicate-name", "ERROR", name,
	"Properties.Name",
	sprintf("CIDR collection %s carries the same name as %s; collection names are unique per account", [name, other]),
	"Give each collection its own name",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_CreateCidrCollection.html") if {
	some name in resources_of_type("AWS::Route53::CidrCollection")
	some other in resources_of_type("AWS::Route53::CidrCollection")
	name < other
	n := _pf_r53z_str(_pf_r53z_props(name), "Name")
	n == _pf_r53z_str(_pf_r53z_props(other), "Name")
}
