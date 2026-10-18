package cdk_preflight

import rego.v1

# The schema requires Match.HttpMatch but none of its members, so an empty
# object passes it. The service rejects it ("At least one of method, pathMatch, headerMatches should be specified to be valid."). Only a literal {} is
# flagged: the schema already rejects any other key, and a Ref / Fn::If stays a
# marker in the raw document.
violation contains make_diag_full("pf-vpclattice-rule-http-match-empty", "ERROR", name,
	"Properties.Match.HttpMatch",
	"A rule Match.HttpMatch is an empty object; the create fails with \"At least one of method, pathMatch, headerMatches should be specified to be valid\"",
	"Set Method, PathMatch or HeaderMatches in HttpMatch",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_HttpMatch.html") if {
	some name in resources_of_type("AWS::VpcLattice::Rule")
	_pf_vpcl_raw(name, ["Match", "HttpMatch"]) == {}
}
