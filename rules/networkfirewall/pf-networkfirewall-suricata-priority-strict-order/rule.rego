package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-networkfirewall-suricata-priority-strict-order", "ERROR", name,
	"Properties.RuleGroup.RulesSource.RulesString",
	sprintf("the rule '%s' uses %s, which a STRICT_ORDER rule group rejects: \"RulesString has invalid keywords. Rule groups that use strict order can't have rules that contain the keywords `priority` or `classtype`\"", [_pf_nfwlib_snip(l), k]),
	"Drop the keyword, or set StatefulRuleOptions.RuleOrder to DEFAULT_ACTION_ORDER",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_RulesSource.html") if {
	some [name, _, l] in _pf_nfwlib_line
	_pf_nfwlib_rule_order(name) == "STRICT_ORDER"
	kws := _pf_nfwlib_option_names(l) & {"priority", "classtype"}
	count(kws) > 0
	k := concat(", ", sort(kws))
}
