package cdk_preflight

import rego.v1

# StatelessRules is a plain array with uniqueItems false and Priority carries
# only its 1..65535 range, so nothing below the service sees the collision.
_pf_nfwspu contains [name, i, p] if {
	some [name, i, r] in _pf_nfwlib_stateless_rules
	p := object.get(r, "Priority", null)
	is_number(p)
}

violation contains make_diag_full("pf-networkfirewall-rulegroup-stateless-priority-unique", "ERROR", name,
	sprintf("Properties.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules[%d].Priority", [i]),
	sprintf("Priority %d is used by %d stateless rules of this rule group; CreateRuleGroup answers \"Priority has duplicate values, parameter: [%d], context: StatelessRulesAndCustomActions.StatelessRules[Priority=%d]\"", [p, count(same), p, p]),
	"Give every stateless rule in the rule group its own Priority",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/stateless-rule-groups-standard.html") if {
	some [name, i, p] in _pf_nfwspu
	same := [j | some [nm, j, q] in _pf_nfwspu; nm == name; q == p]
	count(same) > 1
	i == max(same)
}
