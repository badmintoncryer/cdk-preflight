package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-networkfirewall-suricata-action-supported", "ERROR", name,
	"Properties.RuleGroup.RulesSource.RulesString",
	sprintf("'%s' is not a rule action Network Firewall supports; CreateRuleGroup answers \"reason: Action %s is not supported\" (it takes pass, drop, reject and alert)", [a, a]),
	"Rewrite the rule with pass, drop, reject or alert",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-limitations-caveats.html") if {
	some [name, _, l] in _pf_nfwlib_line
	a := _pf_nfwlib_rule_action(l)
	not a in {"pass", "drop", "reject", "alert"}
}
