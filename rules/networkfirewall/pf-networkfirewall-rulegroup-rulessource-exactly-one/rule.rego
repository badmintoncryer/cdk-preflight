package cdk_preflight

import rego.v1

# The registry schema carries no oneOf/anyOf at all on RulesSource, so both an
# empty RulesSource and one that names two kinds of rules reach the service.
_pf_nfwrso_kinds := {"RulesString", "RulesSourceList", "StatefulRules", "StatelessRulesAndCustomActions"}

_pf_nfwrso_count(name) := count(object.keys(rs) & _pf_nfwrso_kinds) if {
	rs := object.get(_pf_nfwlib_props(name), ["RuleGroup", "RulesSource"], null)
	_pf_countable_entries(rs)
}

violation contains make_diag_full("pf-networkfirewall-rulegroup-rulessource-exactly-one", "ERROR", name,
	"Properties.RuleGroup.RulesSource",
	sprintf("RulesSource names %d of RulesString / RulesSourceList / StatefulRules / StatelessRulesAndCustomActions; CreateRuleGroup answers \"RulesString, RulesSourceList, StatefulRules must set exactly one of them, context: RulesSource\"", [n]),
	"Keep exactly one rules source on the rule group",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_RulesSource.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	n := _pf_nfwrso_count(name)
	n != 1
}
