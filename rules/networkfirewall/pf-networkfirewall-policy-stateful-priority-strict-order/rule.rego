package cdk_preflight

import rego.v1

# "This setting only applies to firewall policies that specify the STRICT_ORDER
# rule order." Priority is optional in the schema and StatefulEngineOptions is a
# separate key, so neither direction is visible below the service. Measured
# 2026-09-25: STRICT_ORDER without Priority answers "Priority cannot be null",
# DEFAULT_ACTION_ORDER with one answers "Priority cannot be provided".
_pf_nfwpsps contains [name, i, "STRICT_ORDER", "Priority cannot be null"] if {
	some [name, kind, i, ref] in _pf_nfwlib_policy_ref
	kind == "Stateful"
	_pf_nfwlib_policy_rule_order(name) == "STRICT_ORDER"
	object.get(ref, "Priority", "__pf_absent") == "__pf_absent"
}

_pf_nfwpsps contains [name, i, "DEFAULT_ACTION_ORDER", "Priority cannot be provided"] if {
	some [name, kind, i, ref] in _pf_nfwlib_policy_ref
	kind == "Stateful"
	_pf_nfwlib_policy_rule_order(name) == "DEFAULT_ACTION_ORDER"
	object.get(ref, "Priority", "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-networkfirewall-policy-stateful-priority-strict-order", "ERROR", name,
	sprintf("Properties.FirewallPolicy.StatefulRuleGroupReferences.%d", [i]),
	sprintf("the policy runs %s; CreateFirewallPolicy answers \"%s, context: StatefulRuleGroupReferences[%d]\"", [o, m, i]),
	"Give every stateful rule group reference a Priority under STRICT_ORDER, and none under DEFAULT_ACTION_ORDER",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_StatefulRuleGroupReference.html") if {
	some [name, i, o, m] in _pf_nfwpsps
}
