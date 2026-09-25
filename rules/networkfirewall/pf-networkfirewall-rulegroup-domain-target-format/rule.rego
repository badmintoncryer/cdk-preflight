package cdk_preflight

import rego.v1

# Targets is an untyped string array in the schema. A wildcard is written as a
# leading "." - the shell-style "*." and a URL scheme are both rejected
# (measured 2026-09-25). Only those two shapes are claimed; anything else is
# left alone rather than guessed at.
_pf_nfwdtf contains [name, i, tgt] if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	tgts := object.get(_pf_nfwlib_props(name), ["RuleGroup", "RulesSource", "RulesSourceList", "Targets"], null)
	_pf_countable_items(tgts)
	some i, tgt in tgts
	is_string(tgt)
}

_pf_nfwdtf_bad(t) if {
	startswith(t, "*")
}

_pf_nfwdtf_bad(t) if {
	contains(t, "://")
}

violation contains make_diag_full("pf-networkfirewall-rulegroup-domain-target-format", "ERROR", name,
	sprintf("Properties.RuleGroup.RulesSource.RulesSourceList.Targets[%d]", [i]),
	sprintf("the target '%s' is neither an explicit domain name nor a leading-dot wildcard; CreateRuleGroup answers \"Targets has invalid format, parameter: [%s], context: RulesSource.RulesSourceList.Targets[%d]\"", [tgt, tgt, i]),
	"Write the domain itself, or prefix it with a single dot (.example.com) to match its subdomains",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_RulesSourceList.html") if {
	some [name, i, tgt] in _pf_nfwdtf
	_pf_nfwdtf_bad(tgt)
}
