package cdk_preflight

import rego.v1

# "You can configure one or more IPv4 or IPv6 addresses in CIDR notation to
# override the default value of Suricata HOME_NET" - and only that one. The
# schema types PolicyVariables.RuleVariables as an open map of IPSets, so any
# key at all gets through. Measured 2026-09-25: even EXTERNAL_NET, the other
# built-in variable a rule group may use, is rejected here.
violation contains make_diag_full("pf-networkfirewall-policy-variables-home-net-only", "ERROR", name,
	sprintf("Properties.FirewallPolicy.PolicyVariables.RuleVariables.%s", [k]),
	sprintf("PolicyVariables.RuleVariables defines '%s'; CreateFirewallPolicy answers \"RuleVariables is invalid, parameter: [%s], context: PolicyVariables.RuleVariables.IPSet.%s\"", [k, k, k]),
	"Keep HOME_NET as the only key of PolicyVariables.RuleVariables",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-policy-settings.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::FirewallPolicy")
	rv := object.get(_pf_nfwlib_fp(name), ["PolicyVariables", "RuleVariables"], null)
	_pf_countable_entries(rv)
	some k in object.keys(rv)
	k != "HOME_NET"
}
