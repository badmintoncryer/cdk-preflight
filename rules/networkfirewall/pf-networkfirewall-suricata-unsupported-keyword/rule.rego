package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-networkfirewall-suricata-unsupported-keyword", "ERROR", name,
	"Properties.RuleGroup.RulesSource.RulesString",
	sprintf("the rule '%s' uses %s; CreateRuleGroup answers \"reason: RuleOptions %s is not supported\"", [_pf_nfwlib_snip(l), k, k]),
	"Remove the keyword; Network Firewall has no rule-local datasets, IP reputation, Lua scripting or file extraction",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-limitations-caveats.html") if {
	some [name, _, l] in _pf_nfwlib_line
	bad := _pf_nfwlib_option_names(l) & {"dataset", "datarep", "iprep", "lua", "luajit", "filestore"}
	count(bad) > 0
	k := concat(", ", sort(bad))
}
