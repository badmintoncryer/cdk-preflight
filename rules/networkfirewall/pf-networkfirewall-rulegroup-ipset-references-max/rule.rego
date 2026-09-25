package cdk_preflight

import rego.v1

# IPSetReferences is a map, so no array maxItems can carry this quota - and the
# quota page puts 5 on the "cannot be changed" side.

violation contains make_diag_full("pf-networkfirewall-rulegroup-ipset-references-max", "ERROR", name,
	"Properties.RuleGroup.ReferenceSets.IPSetReferences",
	sprintf("this rule group declares %d IP set references; the unchangeable quota is 5 and CreateRuleGroup answers \"IPSetReferences limit exceeded, parameter: [%d], context: ReferenceSets\"", [n, n]),
	"Keep at most 5 IP set references per rule group; a prefix list can hold many CIDRs",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-groups-ip-set-references.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	refs := object.get(_pf_nfwlib_props(name), ["RuleGroup", "ReferenceSets", "IPSetReferences"], null)
	_pf_countable_entries(refs)
	n := count(refs)
	n > 5
}
