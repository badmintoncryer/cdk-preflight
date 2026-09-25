package cdk_preflight

import rego.v1

# StatelessDefaultActions is a plain array of strings in the schema, so neither
# "not one standard action in it" nor "two of them" is visible below the service.
# A custom action name may sit next to the one standard action, but on its own it
# still answers "cannot be null or empty" (measured 2026-09-25: ["MyAct"] with
# MyAct defined is rejected, ["aws:pass", "MyAct"] is accepted).
violation contains make_diag_full("pf-networkfirewall-policy-stateless-default-action-standard", "ERROR", name,
	"Properties.FirewallPolicy.StatelessDefaultActions",
	"StatelessDefaultActions names none of aws:pass / aws:drop / aws:forward_to_sfe; CreateFirewallPolicy answers \"StatelessDefaultActions cannot be null or empty, context: StatelessDefaultActions\"",
	"Name exactly one of aws:pass, aws:drop or aws:forward_to_sfe in StatelessDefaultActions",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_FirewallPolicy.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::FirewallPolicy")
	_pf_nfwlib_std_action_count(name, "StatelessDefaultActions") == 0
}

violation contains make_diag_full("pf-networkfirewall-policy-stateless-default-action-standard", "ERROR", name,
	"Properties.FirewallPolicy.StatelessDefaultActions",
	sprintf("StatelessDefaultActions names %d of aws:pass / aws:drop / aws:forward_to_sfe; CreateFirewallPolicy answers \"StatelessDefaultActions cannot exist together, context: StatelessDefaultActions\"", [n]),
	"Name exactly one of aws:pass, aws:drop or aws:forward_to_sfe in StatelessDefaultActions",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_FirewallPolicy.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::FirewallPolicy")
	n := _pf_nfwlib_std_action_count(name, "StatelessDefaultActions")
	n > 1
}
