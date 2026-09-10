package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-cidrcollection-blocks-max-1000", "ERROR", name,
	"Properties.Locations",
	sprintf("the collection lists %d CIDR blocks; a CIDR collection stops at 1000 across all locations", [n]),
	"Split the blocks across more than one CIDR collection",
	"https://docs.aws.amazon.com/general/latest/gr/r53.html") if {
	some name in resources_of_type("AWS::Route53::CidrCollection")
	n := count(_pf_r53z_cidrs(name))
	n > 1000
}
