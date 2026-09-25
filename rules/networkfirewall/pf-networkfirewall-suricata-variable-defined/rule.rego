package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-networkfirewall-suricata-variable-defined", "ERROR", name,
	"Properties.RuleGroup.RulesSource.RulesString",
	sprintf("the rule '%s' uses $%s, which RuleVariables does not declare; CreateRuleGroup answers \"%s cannot be null or empty, context: RuleVariables.IPSets.%s\"", [_pf_nfwlib_snip(l), v, v, v]),
	"Declare the variable under RuleGroup.RuleVariables.IPSets or .PortSets; only HOME_NET and EXTERNAL_NET are built in",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-limitations-caveats.html") if {
	some [name, _, l] in _pf_nfwlib_line
	undef := (_pf_nfwlib_header_vars(l) - _pf_nfwlib_builtin_vars) - _pf_nfwlib_declared_vars(name)
	count(undef) > 0
	v := concat(", ", sort(undef))
}
