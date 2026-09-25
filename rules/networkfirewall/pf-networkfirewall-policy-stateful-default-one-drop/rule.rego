package cdk_preflight

import rego.v1

# "For drop actions, you can choose either none or only one drop action."
# The schema carries no enum at all on StatefulDefaultActions, so the three drop
# names are just strings to every layer below the service. Measured 2026-09-25:
# aws:drop_strict + aws:drop_established and aws:drop_strict +
# aws:drop_established_app_layer are both rejected, while one drop next to any
# number of alert actions is accepted.
_pf_nfwpodr := {"aws:drop_strict", "aws:drop_established", "aws:drop_established_app_layer"}

violation contains make_diag_full("pf-networkfirewall-policy-stateful-default-one-drop", "ERROR", name,
	"Properties.FirewallPolicy.StatefulDefaultActions",
	sprintf("StatefulDefaultActions names %d drop actions (%s); CreateFirewallPolicy answers \"StatefulDefaultActions cannot exist together, parameter: [%s], context: StatefulDefaultActions\"", [count(drops), concat(", ", sort(drops)), concat(", ", sort(drops))]),
	"Keep at most one of aws:drop_strict, aws:drop_established and aws:drop_established_app_layer",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-rule-evaluation-order.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::FirewallPolicy")
	acts := object.get(_pf_nfwlib_fp(name), "StatefulDefaultActions", null)
	_pf_countable_items(acts)
	drops := {a | some a in acts; a in _pf_nfwpodr}
	count(drops) > 1
}
