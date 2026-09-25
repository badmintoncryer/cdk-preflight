package cdk_preflight

import rego.v1

# "If either Drop established or Alert established is selected, you cannot
# select Application drop established (bidirectional), ... and vice versa."
# Measured one pair at a time 2026-09-25: every mix of the two families is
# rejected (drop+alert, alert+alert, both directions), while a pair inside one
# family is accepted and the two aws:*_strict actions sit next to either family.
_pf_nfwpcmp_est := {"aws:drop_established", "aws:alert_established"}

_pf_nfwpcmp_app := {"aws:drop_established_app_layer", "aws:alert_established_app_layer"}

violation contains make_diag_full("pf-networkfirewall-policy-stateful-default-compatible", "ERROR", name,
	"Properties.FirewallPolicy.StatefulDefaultActions",
	sprintf("StatefulDefaultActions mixes the established default rules (%s) with the application-layer ones (%s); CreateFirewallPolicy answers \"StatefulDefaultActions cannot exist together, context: StatefulDefaultActions\"", [concat(", ", sort(e)), concat(", ", sort(p))]),
	"Choose either the established default rules or the application-layer ones, not both",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-rule-evaluation-order.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::FirewallPolicy")
	acts := object.get(_pf_nfwlib_fp(name), "StatefulDefaultActions", null)
	_pf_countable_items(acts)
	chosen := {a | some a in acts; is_string(a)}
	e := chosen & _pf_nfwpcmp_est
	p := chosen & _pf_nfwpcmp_app
	count(e) > 0
	count(p) > 0
}
