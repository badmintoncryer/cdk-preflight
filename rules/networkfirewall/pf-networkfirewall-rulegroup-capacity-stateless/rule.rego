package cdk_preflight

import rego.v1

# A stateless rule costs the product of the element counts of its five match
# settings, not 1 (measured: 3 Sources x 2 Protocols answers "StatelessRules
# capacity exceeded, parameter: [6]"). Capacity cannot be raised afterwards.

violation contains make_diag_full("pf-networkfirewall-rulegroup-capacity-stateless", "ERROR", name,
	"Properties.Capacity",
	sprintf("the stateless rules of this rule group cost %d capacity units (the product of Sources, Destinations, SourcePorts, DestinationPorts and Protocols per rule) but Capacity is %d; CreateRuleGroup answers \"StatelessRules capacity exceeded, parameter: [%d], context: StatelessRulesAndCustomActions.StatelessRules\"", [n, c, n]),
	"Raise Capacity to the summed product of each rule's match settings; a rule group's capacity cannot be changed after it is created",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/nwfw-rule-group-capacity.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	_pf_nfwlib_lit(name, "Properties.Type") == "STATELESS"
	n := _pf_nfwlib_stateless_cost(name)
	raw := resolve(name, "Properties.Capacity")
	raw != null
	c := to_number(raw)
	c < n
}
