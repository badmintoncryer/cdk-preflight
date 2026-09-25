package cdk_preflight

import rego.v1

# "The stateful default action is optional, and is only valid when using the
# strict rule order." StatefulDefaultActions and StatefulEngineOptions are
# independent keys in the schema. An omitted StatefulEngineOptions is
# DEFAULT_ACTION_ORDER and is rejected just like an explicit one (measured
# 2026-09-25: the service quotes back "parameter: [DEFAULT_ACTION_ORDER]").
violation contains make_diag_full("pf-networkfirewall-policy-stateful-default-strict-order", "ERROR", name,
	"Properties.FirewallPolicy.StatefulDefaultActions",
	sprintf("StatefulDefaultActions is set but the policy runs %s; CreateFirewallPolicy answers \"StatefulDefaultActions has invalid rule order, parameter: [%s], context: StatefulDefaultActions\"", [o, o]),
	"Set StatefulEngineOptions.RuleOrder to STRICT_ORDER, or drop StatefulDefaultActions",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_FirewallPolicy.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::FirewallPolicy")
	acts := object.get(_pf_nfwlib_fp(name), "StatefulDefaultActions", null)
	is_array(acts)
	_pf_unconditional_items(acts)
	count(acts) > 0
	o := _pf_nfwlib_policy_rule_order(name)
	o != "STRICT_ORDER"
}
