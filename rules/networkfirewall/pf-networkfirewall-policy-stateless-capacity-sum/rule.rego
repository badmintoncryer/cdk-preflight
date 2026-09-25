package cdk_preflight

import rego.v1

# "Maximum number of stateless rules per firewall policy | 30,000", a quota the
# service will not raise (the stateful row with the same number is adjustable,
# so only this side can be a rule). The sum lives across resources: each
# reference is an ARN, and the capacity is declared on the rule group. Only
# in-template rule groups can be added up, so the rule stays silent as soon as
# one reference is an imported ARN.
_pf_nfwpcap_cap(name, i) := c if {
	gid := _pf_nfwlib_ref_arn(name, "Stateless", i)
	is_string(gid)
	gid in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	c := resolve(gid, "Properties.Capacity")
	is_number(c)
}

_pf_nfwpcap_total(name) := sum(caps) if {
	refs := object.get(_pf_nfwlib_fp(name), "StatelessRuleGroupReferences", null)
	_pf_countable_items(refs)
	count(refs) > 0
	caps := [c |
		some i, _ in refs
		c := _pf_nfwpcap_cap(name, i)
	]
	count(caps) == count(refs)
}

violation contains make_diag_full("pf-networkfirewall-policy-stateless-capacity-sum", "ERROR", name,
	"Properties.FirewallPolicy.StatelessRuleGroupReferences",
	sprintf("the stateless rule groups the policy references declare %d capacity in total; CreateFirewallPolicy answers \"StatelessRuleGroupReferences capacity exceeded, parameter: [%d], context: StatelessRuleGroupReferences\"", [total, total]),
	"Keep the declared Capacity of the referenced stateless rule groups at 30000 or below in total",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/quotas.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::FirewallPolicy")
	total := _pf_nfwpcap_total(name)
	total > 30000
}
