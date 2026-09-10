package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-cidrcollection-ipv4-prefix-max-24", "ERROR", name,
	"Properties.Locations",
	sprintf("CIDR block %s is longer than /24; IP-based routing works on /1 to /24", [c[2]]),
	"Widen the block to /24 or shorter",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_CreateCidrCollection.html") if {
	some name in resources_of_type("AWS::Route53::CidrCollection")
	some c in _pf_r53z_cidrs(name)
	not _pf_r53z_is_v6(c[2])
	_pf_r53z_prefix(c[2]) > 24
}
