package cdk_preflight

import rego.v1

# One stateful rule costs exactly one capacity unit (measured: a 250-rule
# RulesString reports ConsumedCapacity 250), and capacity cannot be raised after
# the rule group is created. RulesSourceList is deliberately left out: its cost
# is a different formula (Targets x TargetTypes + TargetTypes + 1).
_pf_nfwcs_used contains [name, count(_pf_nfwlib_rule_lines(s))] if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	s := _pf_nfwlib_rules_string(name)
}

_pf_nfwcs_used contains [name, count(rs)] if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	rs := object.get(_pf_nfwlib_props(name), ["RuleGroup", "RulesSource", "StatefulRules"], null)
	_pf_countable_items(rs)
}

violation contains make_diag_full("pf-networkfirewall-rulegroup-capacity-stateful", "ERROR", name,
	"Properties.Capacity",
	sprintf("this STATEFUL rule group holds %d rules but Capacity is %d; CreateRuleGroup answers \"StatefulRules capacity exceeded, parameter: [%d], context: RulesSource.StatefulRules\"", [n, c, n]),
	"Give Capacity at least one unit per stateful rule; a rule group's capacity cannot be changed after it is created",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/nwfw-rule-group-capacity.html") if {
	some [name, n] in _pf_nfwcs_used
	_pf_nfwlib_lit(name, "Properties.Type") == "STATEFUL"
	raw := resolve(name, "Properties.Capacity")
	raw != null
	c := to_number(raw)
	c < n
}
