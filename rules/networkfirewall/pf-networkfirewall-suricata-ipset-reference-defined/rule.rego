package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-networkfirewall-suricata-ipset-reference-defined", "ERROR", name,
	"Properties.RuleGroup.RulesSource.RulesString",
	sprintf("the rule '%s' uses @%s, which ReferenceSets.IPSetReferences does not declare; CreateRuleGroup answers \"%s cannot be null or empty, context: ReferenceSets.IPSetReferences.%s\"", [_pf_nfwlib_snip(l), r, r, r]),
	"Declare the IP set reference under RuleGroup.ReferenceSets.IPSetReferences with the prefix list ARN it stands for",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-groups-ip-set-references.html") if {
	some [name, _, l] in _pf_nfwlib_line
	undef := _pf_nfwlib_header_refs(l) - _pf_nfwlib_declared_refs(name)
	count(undef) > 0
	r := concat(", ", sort(undef))
}
