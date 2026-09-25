package cdk_preflight

import rego.v1

# Network Firewall appends a gid of its own to every rule it accepts (the 16
# characters that pf-networkfirewall-suricata-rule-max-length budgets for), so a
# rule that carries one is rejected outright - with a message of its own, not the
# "RuleOptions ... is not supported" that the unsupported keywords get.

violation contains make_diag_full("pf-networkfirewall-suricata-gid-not-allowed", "ERROR", name,
	"Properties.RuleGroup.RulesSource.RulesString",
	sprintf("the rule '%s' sets gid; CreateRuleGroup answers \"GIDs are not allowed. Illegal option(s): [gid:...]\"", [_pf_nfwlib_snip(l)]),
	"Drop the gid option; Network Firewall assigns the group id itself",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-limitations-caveats.html") if {
	some [name, _, l] in _pf_nfwlib_line
	"gid" in _pf_nfwlib_option_names(l)
}
