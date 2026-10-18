package cdk_preflight

import rego.v1

# The schema requires DefaultAction but none of its members, so an empty
# object passes it. The service rejects it ("Action is required in Listener's defaultAction field."). Only a literal {} is
# flagged: the schema already rejects any other key, and a Ref / Fn::If stays a
# marker in the raw document.
violation contains make_diag_full("pf-vpclattice-listener-default-action-empty", "ERROR", name,
	"Properties.DefaultAction",
	"A listener DefaultAction is an empty object; the create fails with \"Action is required in Listener's defaultAction field\"",
	"Set DefaultAction.Forward or DefaultAction.FixedResponse",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateListener.html") if {
	some name in resources_of_type("AWS::VpcLattice::Listener")
	_pf_vpcl_raw(name, ["DefaultAction"]) == {}
}
