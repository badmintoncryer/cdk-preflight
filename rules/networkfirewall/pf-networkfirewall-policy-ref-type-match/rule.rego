package cdk_preflight

import rego.v1

# StatefulRuleGroupReferences and StatelessRuleGroupReferences both take a plain
# ResourceArn string, so nothing below the service notices a policy that lists a
# STATELESS rule group among its stateful references. Two wirings reach here:
# a reference to a rule group in the same template (Ref / Fn::GetAtt, which is
# what CDK emits - resolve() hands back the logical id, and the Type is a
# property of that resource), and an imported ARN, whose fifth segment already
# says which kind it is. Measured 2026-09-25: the ARN wiring answers "rule group
# ARN is of incorrect entity type" before it checks the rule group exists.
_pf_nfwprtm_type(name, kind, i) := t if {
	id := _pf_nfwlib_ref_arn(name, kind, i)
	is_string(id)
	id in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	t := _pf_nfwlib_lit(id, "Properties.Type")
}

_pf_nfwprtm_seg := {"stateful-rulegroup": "STATEFUL", "stateless-rulegroup": "STATELESS"}

# One body, keyed on the resource segment: two `contains` bodies could both hold
# for a hand-written ARN, and a complete rule with two outputs is an eval error
# that silences the whole pack for that template.
_pf_nfwprtm_type(name, kind, i) := t if {
	arn := _pf_nfwlib_ref_arn(name, kind, i)
	is_string(arn)
	not input.resources[arn]
	parts := split(arn, ":")
	count(parts) >= 6
	t := _pf_nfwprtm_seg[split(parts[5], "/")[0]]
}

violation contains make_diag_full("pf-networkfirewall-policy-ref-type-match", "ERROR", name,
	sprintf("Properties.FirewallPolicy.%sRuleGroupReferences.%d.ResourceArn", [kind, i]),
	sprintf("%sRuleGroupReferences[%d] points at a %s rule group; CreateFirewallPolicy answers \"rule group ARN is of incorrect entity type\"", [kind, i, t]),
	"Point stateful references at STATEFUL rule groups and stateless references at STATELESS ones",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_StatefulRuleGroupReference.html") if {
	some [name, kind, i, _] in _pf_nfwlib_policy_ref
	t := _pf_nfwprtm_type(name, kind, i)
	t != upper(kind)
}
