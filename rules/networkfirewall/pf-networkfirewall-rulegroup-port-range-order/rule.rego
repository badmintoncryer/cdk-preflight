package cdk_preflight

import rego.v1

# Both ends carry their own 0..65535 range in the schema and nothing ties them
# together. Same constraint and same message as the TLS inspection scope's port
# ranges, one resource type over.
_pf_nfwrgpr contains [name, i, key, pi, f, t] if {
	some [name, i, r] in _pf_nfwlib_stateless_rules
	some key in {"SourcePorts", "DestinationPorts"}
	ranges := object.get(r, ["RuleDefinition", "MatchAttributes", key], null)
	is_array(ranges)
	some pi, pr in ranges
	is_object(pr)
	f := object.get(pr, "FromPort", null)
	t := object.get(pr, "ToPort", null)
	is_number(f)
	is_number(t)
}

violation contains make_diag_full("pf-networkfirewall-rulegroup-port-range-order", "ERROR", name,
	sprintf("Properties.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules[%d].RuleDefinition.MatchAttributes.%s[%d]", [i, key, pi]),
	sprintf("FromPort %v is above ToPort %v; CreateRuleGroup answers \"FromPort, ToPort is not within the bound, parameter: [%v, %v]\"", [f, t, f, t]),
	"Put the lower port in FromPort",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_PortRange.html") if {
	some [name, i, key, pi, f, t] in _pf_nfwrgpr
	f > t
}
