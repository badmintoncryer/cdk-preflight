package cdk_preflight

import rego.v1

# The schema requires Match.HttpMatch.PathMatch.Match but none of its members, so an empty
# object passes it. The service rejects it ("Invalid path match typePathMatchType()"). Only a literal {} is
# flagged: the schema already rejects any other key, and a Ref / Fn::If stays a
# marker in the raw document.
violation contains make_diag_full("pf-vpclattice-rule-path-match-empty", "ERROR", name,
	"Properties.Match.HttpMatch.PathMatch.Match",
	"A rule PathMatch.Match is an empty object; the create fails with \"Invalid path match typePathMatchType()\"",
	"Set PathMatch.Match.Exact or PathMatch.Match.Prefix",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_PathMatch.html") if {
	some name in resources_of_type("AWS::VpcLattice::Rule")
	_pf_vpcl_raw(name, ["Match", "HttpMatch", "PathMatch", "Match"]) == {}
}
