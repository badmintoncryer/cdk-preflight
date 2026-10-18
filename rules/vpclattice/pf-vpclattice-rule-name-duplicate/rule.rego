package cdk_preflight

import rego.v1

# Name is not the primary identifier, so the schema says nothing about
# uniqueness, but CreateRule rejects a name the listener already has ("Rule
# with name ... already exists in listener-... listener"). Only resources in one template that name the same ListenerIdentifier (the
# same logical id or the same literal) are compared, and only explicit values.
violation contains make_diag_full("pf-vpclattice-rule-name-duplicate", "ERROR", name,
	"Properties.Name",
	sprintf("Rule name %v is already used by '%s' under the same ListenerIdentifier; the create fails with \"Rule with name ... already exists in listener-... listener.\"", [v, other]),
	"Give each rule of the listener its own Name",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateRule.html") if {
	some name in resources_of_type("AWS::VpcLattice::Rule")
	p := resolve(name, "Properties.ListenerIdentifier")
	is_string(p)
	v := resolve(name, "Properties.Name")
	_pf_vpcl_lit(v)
	some other in resources_of_type("AWS::VpcLattice::Rule")
	other < name
	resolve(other, "Properties.ListenerIdentifier") == p
	resolve(other, "Properties.Name") == v
}
