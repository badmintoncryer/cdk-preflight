package cdk_preflight

import rego.v1

# "The settings for your rule groups must match the settings for the firewall
# policy that they belong to." The two RuleOrder keys sit on different resources
# and the ARN does not carry the setting, so this is only decidable when the
# rule group is in the same template - which is the shape CDK emits. Both sides
# default to DEFAULT_ACTION_ORDER when the key is omitted, and the service
# rejects the mismatch either way round (measured 2026-09-25).
violation contains make_diag_full("pf-networkfirewall-policy-rule-order-match", "ERROR", name,
	sprintf("Properties.FirewallPolicy.StatefulRuleGroupReferences.%d.ResourceArn", [i]),
	sprintf("the policy runs %s but rule group '%s' runs %s; CreateFirewallPolicy answers \"ResourceArn has invalid rule order, context: StatefulRuleGroupReferences[%d].ResourceArn\"", [po, gid, gro, i]),
	"Set StatefulRuleOptions.RuleOrder on the rule group to the policy's StatefulEngineOptions.RuleOrder",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-rule-evaluation-order.html") if {
	some [name, kind, i, _] in _pf_nfwlib_policy_ref
	kind == "Stateful"
	gid := _pf_nfwlib_ref_arn(name, kind, i)
	is_string(gid)
	gid in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	po := _pf_nfwlib_policy_rule_order(name)
	gro := _pf_nfwlib_group_rule_order(gid)
	po != gro
}
