package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-cidrcollection-cidr-item-length", "ERROR", name,
	"Properties.Locations",
	sprintf("CIDR block entry %s is %d characters; the API takes 1 to 50", [c[2], count(c[2])]),
	"Write the CIDR block in its normal form",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_CreateCidrCollection.html") if {
	some name in resources_of_type("AWS::Route53::CidrCollection")
	some c in _pf_r53z_cidrs(name)
	count(c[2]) > 50
}
