package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-networkfirewall-suricata-sid-required", "ERROR", name,
	"Properties.RuleGroup.RulesSource.RulesString",
	sprintf("the Suricata rule '%s' has no sid option; CreateRuleGroup answers \"stateful rule is invalid, rule: ..., reason: sid not assigned\"", [_pf_nfwlib_snip(l)]),
	"Give every rule its own sid option, e.g. (msg:\"...\"; sid:1;)",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/stateful-rule-groups-suricata.html") if {
	some [name, _, l] in _pf_nfwlib_line
	not "sid" in _pf_nfwlib_option_names(l)
}
