package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-cidrcollection-cidr-item-blank", "ERROR", name,
	"Properties.Locations",
	"a CidrList entry is empty or only whitespace",
	"Remove the empty entry, or write the CIDR block",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_CreateCidrCollection.html") if {
	some name in resources_of_type("AWS::Route53::CidrCollection")
	some c in _pf_r53z_cidrs(name)
	trim_space(c[2]) == ""
}
