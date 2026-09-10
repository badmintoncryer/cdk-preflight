package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-cidrcollection-duplicate-cidr-block", "ERROR", name,
	"Properties.Locations",
	sprintf("CIDR block %s appears more than once in the collection; Route 53 answers CidrBlockInUseException", [a[2]]),
	"Keep each CIDR block in a single location",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_CreateCidrCollection.html") if {
	some name in resources_of_type("AWS::Route53::CidrCollection")
	some a in _pf_r53z_cidrs(name)
	count([b | some b in _pf_r53z_cidrs(name); b[2] == a[2]]) > 1
}
