package cdk_preflight

import rego.v1

# Type and RulesSource are independent in the schema, so a STATEFUL group can be
# written with stateless rules and the other way round. The service names the
# stateless key either way, with two different verbs.
_pf_nfwtsm_stateful_kinds := {"RulesString", "RulesSourceList", "StatefulRules"}

_pf_nfwtsm_bad contains [name, "STATELESS", k, "StatelessRulesAndCustomActions cannot be null"] if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	_pf_nfwlib_lit(name, "Properties.Type") == "STATELESS"
	rs := object.get(_pf_nfwlib_props(name), ["RuleGroup", "RulesSource"], null)
	_pf_countable_entries(rs)
	some k in object.keys(rs) & _pf_nfwtsm_stateful_kinds
}

_pf_nfwtsm_bad contains [name, "STATEFUL", "StatelessRulesAndCustomActions", "StatelessRulesAndCustomActions is invalid"] if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	_pf_nfwlib_lit(name, "Properties.Type") == "STATEFUL"
	rs := object.get(_pf_nfwlib_props(name), ["RuleGroup", "RulesSource"], null)
	_pf_countable_entries(rs)
	"StatelessRulesAndCustomActions" in object.keys(rs)
}

violation contains make_diag_full("pf-networkfirewall-rulegroup-type-source-match", "ERROR", name,
	sprintf("Properties.RuleGroup.RulesSource.%s", [k]),
	sprintf("a %s rule group cannot carry %s; CreateRuleGroup answers \"%s, context: RulesSource.StatelessRulesAndCustomActions\"", [t, k, m]),
	"Give the rule group the rules source its Type takes: StatelessRulesAndCustomActions for STATELESS, RulesString / RulesSourceList / StatefulRules for STATEFUL",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-group-settings.html") if {
	some [name, t, k, m] in _pf_nfwtsm_bad
}
