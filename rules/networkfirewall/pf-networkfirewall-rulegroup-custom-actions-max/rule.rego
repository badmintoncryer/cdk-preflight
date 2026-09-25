package cdk_preflight

import rego.v1

# The registry schema gives CustomActions no maxItems; 10 is on the "cannot be
# changed" side of the quota page.

violation contains make_diag_full("pf-networkfirewall-rulegroup-custom-actions-max", "ERROR", name,
	"Properties.RuleGroup.RulesSource.StatelessRulesAndCustomActions.CustomActions",
	sprintf("this rule group defines %d custom actions; the unchangeable quota is 10 and CreateRuleGroup answers \"ActionDefinition limit exceeded, parameter: [%d], context: StatelessRulesAndCustomActions.CustomActions\"", [n, n]),
	"Keep at most 10 custom actions per stateless rule group; one PublishMetricAction can carry several dimensions",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/quotas.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	cas := object.get(_pf_nfwlib_props(name), ["RuleGroup", "RulesSource", "StatelessRulesAndCustomActions", "CustomActions"], null)
	_pf_countable_items(cas)
	n := count(cas)
	n > 10
}
