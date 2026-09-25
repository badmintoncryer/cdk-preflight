package cdk_preflight

import rego.v1

# Override is an ordinary optional key on every StatefulRuleGroupReference, but
# the service only accepts it on a reference to an AWS managed rule group
# (measured 2026-09-25 - the rule order the doc ties it to turned out not to
# matter). A managed rule group carries "aws-managed" where an ARN normally
# carries the account id, so the account segment is what decides; a rule group
# declared in this template is the account's own by construction.
_pf_nfwpovr_own(name, i) if {
	id := _pf_nfwlib_ref_arn(name, "Stateful", i)
	is_string(id)
	id in resources_of_type("AWS::NetworkFirewall::RuleGroup")
}

_pf_nfwpovr_own(name, i) if {
	arn := _pf_nfwlib_ref_arn(name, "Stateful", i)
	is_string(arn)
	not input.resources[arn]
	parts := split(arn, ":")
	count(parts) >= 6
	regex.match(`^[0-9]{12}$`, parts[4])
}

violation contains make_diag_full("pf-networkfirewall-policy-override-managed-only", "ERROR", name,
	sprintf("Properties.FirewallPolicy.StatefulRuleGroupReferences.%d.Override", [i]),
	sprintf("StatefulRuleGroupReferences[%d] overrides a rule group this account owns; CreateFirewallPolicy answers \"rule group must be a managed resource\"", [i]),
	"Drop Override, or point the reference at an AWS managed rule group",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_StatefulRuleGroupReference.html") if {
	some [name, kind, i, ref] in _pf_nfwlib_policy_ref
	kind == "Stateful"
	object.get(ref, "Override", "__pf_absent") != "__pf_absent"
	_pf_nfwpovr_own(name, i)
}
