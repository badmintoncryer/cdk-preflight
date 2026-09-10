package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-cidrcollection-zero-prefix-default-location", "ERROR", name,
	"Properties.Locations",
	sprintf("CIDR block %s has a zero-length prefix; only the reserved default location * can hold it, and that location cannot be created", [c[2]]),
	"Use a concrete prefix, and let unmatched queries fall back to the default location",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_CreateCidrCollection.html") if {
	some name in resources_of_type("AWS::Route53::CidrCollection")
	some c in _pf_r53z_cidrs(name)
	_pf_r53z_prefix(c[2]) == 0
}
