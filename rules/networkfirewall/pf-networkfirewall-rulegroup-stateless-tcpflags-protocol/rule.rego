package cdk_preflight

import rego.v1

# Same shape as the port rule, one protocol narrower: TCPFlags is "only used for
# protocol 6 (TCP)" and the service rejects any other explicit protocol list.
_pf_nfwstp contains [name, i] if {
	some [name, i, r] in _pf_nfwlib_stateless_rules
	ma := object.get(r, ["RuleDefinition", "MatchAttributes"], null)
	is_object(ma)
	protos := object.get(ma, "Protocols", null)
	_pf_countable_items(protos)
	count([p | some p in protos; is_number(p)]) == count(protos)
	count(protos) > 0
	count([p | some p in protos; p == 6]) == 0
	flags := object.get(ma, "TCPFlags", null)
	is_array(flags)
	count(flags) > 0
}

violation contains make_diag_full("pf-networkfirewall-rulegroup-stateless-tcpflags-protocol", "ERROR", name,
	sprintf("Properties.RuleGroup.RulesSource.StatelessRulesAndCustomActions.StatelessRules[%d].RuleDefinition.MatchAttributes.TCPFlags", [i]),
	"TCPFlags is set but Protocols does not name 6 (TCP); CreateRuleGroup answers \"TCPFlags, Protocols cannot exist together, context: ...MatchAttributes.TCPFlags\"",
	"Add 6 to Protocols, or drop the TCPFlags match",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_MatchAttributes.html") if {
	some [name, i] in _pf_nfwstp
}
