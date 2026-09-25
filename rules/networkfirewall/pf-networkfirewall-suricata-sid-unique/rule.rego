package cdk_preflight

import rego.v1

# The sid of every rule line, in order, so a repeat can be counted.
_pf_nfwsid_sids(name) := [v |
	some l in _pf_nfwlib_rule_lines(_pf_nfwlib_rules_string(name))
	vs := _pf_nfwlib_option_values(l, "sid")
	count(vs) > 0
	v := vs[0]
]

_pf_nfwsid_occurrences(arr, x) := count([1 |
	some y in arr
	y == x
])

violation contains make_diag_full("pf-networkfirewall-suricata-sid-unique", "ERROR", name,
	"Properties.RuleGroup.RulesSource.RulesString",
	sprintf("sid %s is used by more than one Suricata rule in this rule group; CreateRuleGroup answers \"stateful rule is invalid, reason: Duplicate signature ...\"", [sid]),
	"Give every rule in the rule group its own sid",
	"https://docs.suricata.io/en/suricata-8.0.3/rules/meta.html#sid") if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	sids := _pf_nfwsid_sids(name)
	some sid in sids
	_pf_nfwsid_occurrences(sids, sid) > 1
}
