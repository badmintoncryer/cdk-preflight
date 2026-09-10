package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-cidrcollection-ipv6-prefix-max-48", "ERROR", name,
	"Properties.Locations",
	sprintf("CIDR block %s is longer than /48; IP-based routing works on /1 to /48 for IPv6", [c[2]]),
	"Widen the block to /48 or shorter",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_CreateCidrCollection.html") if {
	some name in resources_of_type("AWS::Route53::CidrCollection")
	some c in _pf_r53z_cidrs(name)
	_pf_r53z_is_v6(c[2])
	_pf_r53z_prefix(c[2]) > 48
}
