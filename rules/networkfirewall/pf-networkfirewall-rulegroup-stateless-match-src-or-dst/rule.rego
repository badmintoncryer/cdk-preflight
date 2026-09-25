package cdk_preflight

import rego.v1

# Every field of MatchAttributes is optional in the schema, so an empty
# MatchAttributes {} synthesizes cleanly out of both the L1 and the L2 - and the
# service rejects it: at least one of Sources and Destinations must be there.
_pf_nfwmsd_empty(ma, key) if {
	v := object.get(ma, key, [])
	is_array(v)
	count(v) == 0
}

violation contains make_diag_full("pf-networkfirewall-rulegroup-stateless-match-src-or-dst", "ERROR", name,
	sprintf("Properties.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules[%d].RuleDefinition.MatchAttributes", [i]),
	"MatchAttributes sets neither Sources nor Destinations; CreateRuleGroup answers \"Sources, Destinations cannot be null or empty, context: StatelessRulesAndCustomActions.StatelessRules[...].RuleDefinition.MatchAttributes\"",
	"Match on at least one address: Sources or Destinations, 0.0.0.0/0 for any",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_MatchAttributes.html") if {
	some [name, i, r] in _pf_nfwlib_stateless_rules
	ma := object.get(r, ["RuleDefinition", "MatchAttributes"], null)
	is_object(ma)
	not _pf_ll_conditional(ma)
	_pf_nfwmsd_empty(ma, "Sources")
	_pf_nfwmsd_empty(ma, "Destinations")
}
