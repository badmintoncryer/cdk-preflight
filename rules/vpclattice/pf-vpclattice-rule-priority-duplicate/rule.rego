package cdk_preflight

import rego.v1

# CreateRule rejects a priority the listener already uses ("Rule with
# priority 50 already exist!"). Only resources in one template that name the same ListenerIdentifier (the
# same logical id or the same literal) are compared, and only explicit values.
violation contains make_diag_full("pf-vpclattice-rule-priority-duplicate", "ERROR", name,
	"Properties.Priority",
	sprintf("Rule Priority %v is already used by '%s' under the same ListenerIdentifier; the create fails with \"Rule with priority 50 already exist!\"", [v, other]),
	"Give each rule of the listener its own Priority",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateRule.html") if {
	some name in resources_of_type("AWS::VpcLattice::Rule")
	p := resolve(name, "Properties.ListenerIdentifier")
	is_string(p)
	v := resolve(name, "Properties.Priority")
	_pf_vpcl_lit(v)
	some other in resources_of_type("AWS::VpcLattice::Rule")
	other < name
	resolve(other, "Properties.ListenerIdentifier") == p
	resolve(other, "Properties.Priority") == v
}
