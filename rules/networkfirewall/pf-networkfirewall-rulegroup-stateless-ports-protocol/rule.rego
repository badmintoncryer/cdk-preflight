package cdk_preflight

import rego.v1

# "This setting is only used for protocols 6 (TCP) and 17 (UDP)" turns out to be
# a rejection, not a silent no-op (measured 2026-09-25; the survey's first probe
# read as a no-op only because its MatchAttributes had no Sources at all).
# An absent Protocols means every protocol, so only an explicit list fires.
_pf_nfwspp contains [name, i, key] if {
	some [name, i, r] in _pf_nfwlib_stateless_rules
	ma := object.get(r, ["RuleDefinition", "MatchAttributes"], null)
	is_object(ma)
	protos := object.get(ma, "Protocols", null)
	_pf_countable_items(protos)
	count([p | some p in protos; is_number(p)]) == count(protos)
	count(protos) > 0
	count([p | some p in protos; p in {6, 17}]) == 0
	some key in {"SourcePorts", "DestinationPorts"}
	ports := object.get(ma, key, null)
	is_array(ports)
	count(ports) > 0
}

violation contains make_diag_full("pf-networkfirewall-rulegroup-stateless-ports-protocol", "ERROR", name,
	sprintf("Properties.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules[%d].RuleDefinition.MatchAttributes.%s", [i, key]),
	sprintf("%s is set but Protocols names neither 6 (TCP) nor 17 (UDP); CreateRuleGroup answers \"%s, Protocols cannot exist together, context: ...MatchAttributes.%s\"", [key, key, key]),
	"Add 6 or 17 to Protocols, or drop the port match",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_MatchAttributes.html") if {
	some [name, i, key] in _pf_nfwspp
}
