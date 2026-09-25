package cdk_preflight

import rego.v1

# "You must ensure that the priority settings are unique within each policy."
# StatefulRuleGroupReferences is a plain array with uniqueItems false, and
# Priority carries no cross-element constraint, so the collision only surfaces at
# CreateFirewallPolicy.
_pf_nfwpsfu contains [name, i, p] if {
	some [name, kind, i, ref] in _pf_nfwlib_policy_ref
	kind == "Stateful"
	p := object.get(ref, "Priority", null)
	is_number(p)
}

violation contains make_diag_full("pf-networkfirewall-policy-stateful-priority-unique", "ERROR", name,
	sprintf("Properties.FirewallPolicy.StatefulRuleGroupReferences.%d.Priority", [i]),
	sprintf("Priority %d is used by %d StatefulRuleGroupReferences entries; CreateFirewallPolicy answers \"Priority has duplicate values, parameter: [%d], context: StatefulRuleGroupReferences[Priority=%d]\"", [p, count(same), p, p]),
	"Give every StatefulRuleGroupReferences entry its own Priority",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_StatefulRuleGroupReference.html") if {
	some [name, i, p] in _pf_nfwpsfu
	same := [j | some [nm, j, q] in _pf_nfwpsfu; nm == name; q == p]
	count(same) > 1
	i == max(same)
}
