package cdk_preflight

import rego.v1

# Targets is a plain array of strings with uniqueItems false, so no layer below
# the service compares the entries. The service strips the leading "." of a
# wildcard target before it compares, so ".example.com" next to "example.com" is
# a duplicate (measured 2026-09-25; ".a.example.com" with "a.example.com" too,
# while "Example.com" next to "example.com" is accepted - the comparison is
# case-sensitive).
_pf_nfwdtu contains [name, i, key] if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	targets := object.get(_pf_nfwlib_props(name), ["RuleGroup", "RulesSource", "RulesSourceList", "Targets"], null)
	_pf_countable_items(targets)
	some i, t in targets
	is_string(t)
	key := trim_prefix(t, ".")
}

violation contains make_diag_full("pf-networkfirewall-rulegroup-domain-target-unique", "ERROR", name,
	sprintf("Properties.RuleGroup.RulesSource.RulesSourceList.Targets.%d", [i]),
	sprintf("%d targets reduce to '%s' once the leading wildcard dot is stripped; CreateRuleGroup answers \"Targets has duplicate values, parameter: [%s], context: RulesSource.RulesSourceList.Targets[%d]\"", [count(same), key, key, i]),
	"Keep one entry per domain: the wildcard form '.example.com' already covers 'example.com'",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_RulesSourceList.html") if {
	some [name, i, key] in _pf_nfwdtu
	same := [j | some [nm, j, k] in _pf_nfwdtu; nm == name; k == key]
	count(same) > 1
	i == max(same)
}
