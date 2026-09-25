package cdk_preflight

import rego.v1

# The registry schema gives Capacity neither a minimum nor a maximum. 30,000 is
# on the "cannot be changed" side of the quota page, for both rule group types.

violation contains make_diag_full("pf-networkfirewall-rulegroup-capacity-max", "ERROR", name,
	"Properties.Capacity",
	sprintf("Capacity is %d; the unchangeable quota is 30000 and CreateRuleGroup answers \"Capacity capacity exceeded, parameter: [%d], context: Capacity\"", [c, c]),
	"Keep Capacity at 30000 or below and split the rules over several rule groups",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/quotas.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::RuleGroup")
	raw := resolve(name, "Properties.Capacity")
	raw != null
	c := to_number(raw)
	c > 30000
}
