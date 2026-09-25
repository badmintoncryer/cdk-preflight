package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-networkfirewall-suricata-rule-max-length", "ERROR", name,
	"Properties.RuleGroup.RulesSource.RulesString",
	sprintf("the Suricata rule starting '%s' is %d characters long; Network Firewall appends its own 16-character gid option and then answers \"reason: Rule exceeds max length (8192)\", so a template has room for 8175", [_pf_nfwlib_snip(l), count(l)]),
	"Split the rule, or shorten its content / pcre / msg options",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/quotas.html") if {
	some [name, _, l] in _pf_nfwlib_line
	count(l) > 8175
}
