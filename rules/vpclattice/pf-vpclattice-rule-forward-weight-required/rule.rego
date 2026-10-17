package cdk_preflight

import rego.v1

# Weight is optional in the schema, and a single target group needs none. With
# two or more target groups, the service rejects any entry without a Weight
# ("Target group weights are required when more than 1 target group is provided").
violation contains make_diag_full("pf-vpclattice-rule-forward-weight-required", "ERROR", name,
	sprintf("Properties.Action.Forward.TargetGroups.%d.Weight", [it.index]),
	"A rule forward action lists more than one target group but this entry has no Weight; the create fails with \"Target group weights are required when more than 1 target group is provided\"",
	"Give every target group in Forward.TargetGroups a Weight",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/listener-rules.html") if {
	some name in resources_of_type("AWS::VpcLattice::Rule")
	_pf_countable_list(name, "Properties.Action.Forward.TargetGroups")
	l := flatten_list(name, "Properties.Action.Forward.TargetGroups")
	count(l) > 1
	some it in l
	object.get(it.value, "Weight", "__pf_absent") == "__pf_absent"
}
