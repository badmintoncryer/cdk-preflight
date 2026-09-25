package cdk_preflight

import rego.v1

# Actions is a free-form string array in the schema. The service wants exactly
# one of the three standard actions in it; custom action names ride alongside
# but do not stand in for one (a rule with only a custom action is "null or
# empty" as far as the standard action goes).
_pf_nfwsas_standard := {"aws:pass", "aws:drop", "aws:forward_to_sfe"}

_pf_nfwsas_phrase(0) := "cannot be null or empty"

_pf_nfwsas_phrase(n) := "cannot exist together" if {
	n > 1
}

violation contains make_diag_full("pf-networkfirewall-rulegroup-stateless-action-standard", "ERROR", name,
	sprintf("Properties.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules[%d].RuleDefinition.Actions", [i]),
	sprintf("this stateless rule names %d of aws:pass / aws:drop / aws:forward_to_sfe; CreateRuleGroup answers \"Actions %s, context: StatelessRulesAndCustomActions.StatelessRules[...].RuleDefinition.Actions\"", [n, _pf_nfwsas_phrase(n)]),
	"Name exactly one of aws:pass, aws:drop or aws:forward_to_sfe in the rule's Actions",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-action.html") if {
	some [name, i, r] in _pf_nfwlib_stateless_rules
	acts := object.get(r, ["RuleDefinition", "Actions"], null)
	_pf_countable_items(acts)
	count([a | some a in acts; is_string(a)]) == count(acts)
	n := count([a | some a in acts; a in _pf_nfwsas_standard])
	n != 1
}
