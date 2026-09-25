package cdk_preflight

import rego.v1

# "Maximum number of stateful rule groups per firewall policy | 20", a quota the
# service will not raise. The schema puts no maxItems on the array.
violation contains make_diag_full("pf-networkfirewall-policy-stateful-refs-max", "ERROR", name,
	"Properties.FirewallPolicy.StatefulRuleGroupReferences",
	sprintf("the policy references %d stateful rule groups; CreateFirewallPolicy answers \"StatefulRuleGroupReferences limit exceeded, parameter: [%d], context: StatefulRuleGroupReferences\"", [n, n]),
	"Keep at most 20 stateful rule group references on a firewall policy",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/quotas.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::FirewallPolicy")
	refs := object.get(_pf_nfwlib_fp(name), "StatefulRuleGroupReferences", null)
	_pf_countable_items(refs)
	n := count(refs)
	n > 20
}
