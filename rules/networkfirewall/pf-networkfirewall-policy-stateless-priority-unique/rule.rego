package cdk_preflight

import rego.v1

# "You must ensure that the priority settings are unique within each policy."
# StatelessRuleGroupReferences is a plain array with uniqueItems false, and
# Priority carries no cross-element constraint, so the collision only surfaces at
# CreateFirewallPolicy.
_pf_nfwpslu contains [name, i, p] if {
	some [name, kind, i, ref] in _pf_nfwlib_policy_ref
	kind == "Stateless"
	p := object.get(ref, "Priority", null)
	is_number(p)
}

violation contains make_diag_full("pf-networkfirewall-policy-stateless-priority-unique", "ERROR", name,
	sprintf("Properties.FirewallPolicy.StatelessRuleGroupReferences.%d.Priority", [i]),
	sprintf("Priority %d is used by %d StatelessRuleGroupReferences entries; CreateFirewallPolicy answers \"Priority has duplicate values, parameter: [%d], context: StatelessRuleGroupReferences[Priority=%d]\"", [p, count(same), p, p]),
	"Give every StatelessRuleGroupReferences entry its own Priority",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_StatelessRuleGroupReference.html") if {
	some [name, i, p] in _pf_nfwpslu
	same := [j | some [nm, j, q] in _pf_nfwpslu; nm == name; q == p]
	count(same) > 1
	i == max(same)
}
