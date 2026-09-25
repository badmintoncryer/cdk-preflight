package cdk_preflight

import rego.v1

# Two keys of IPSetReferences may not carry the same ReferenceArn, even though
# the map's keys are already distinct (measured 2026-09-25: the service answers
# before it resolves the prefix list). Comparing the raw property value makes
# this work for Fn::GetAtt too, which is the shape CDK emits.
_pf_nfwrua contains [name, key, arn] if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	refs := object.get(_pf_nfwlib_props(name), ["RuleGroup", "ReferenceSets", "IPSetReferences"], null)
	_pf_countable_entries(refs)
	some key, v in refs
	arn := object.get(v, "ReferenceArn", null)
	arn != null
}

violation contains make_diag_full("pf-networkfirewall-rulegroup-ipset-reference-arn-unique", "ERROR", name,
	sprintf("Properties.RuleGroup.ReferenceSets.IPSetReferences.%s.ReferenceArn", [key]),
	sprintf("the IP set references %s all carry the same ReferenceArn; CreateRuleGroup answers \"IPSetReferences is invalid, context: ReferenceSets\"", [names]),
	"Keep one reference per prefix list; several Suricata rules can use the same @name",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-groups-ip-set-references.html") if {
	some [name, key, arn] in _pf_nfwrua
	sharing := {k | some [nm, k, a] in _pf_nfwrua; nm == name; a == arn}
	count(sharing) > 1
	key == max(sharing)
	names := concat(", ", sort(sharing))
}
