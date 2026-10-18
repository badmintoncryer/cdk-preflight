package cdk_preflight

import rego.v1

# The schema requires Action but none of its members, so an empty
# object passes it. The service rejects it ("Action is required in Rule's action field."). Only a literal {} is
# flagged: the schema already rejects any other key, and a Ref / Fn::If stays a
# marker in the raw document.
violation contains make_diag_full("pf-vpclattice-rule-action-empty", "ERROR", name,
	"Properties.Action",
	"A rule Action is an empty object; the create fails with \"Action is required in Rule's action field\"",
	"Set Action.Forward or Action.FixedResponse",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateRule.html") if {
	some name in resources_of_type("AWS::VpcLattice::Rule")
	_pf_vpcl_raw(name, ["Action"]) == {}
}
