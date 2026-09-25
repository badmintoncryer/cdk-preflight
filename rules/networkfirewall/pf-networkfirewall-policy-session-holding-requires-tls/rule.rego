package cdk_preflight

import rego.v1

# "Requires an associated TLS Inspection configuration." EnableTLSSessionHolding
# and TLSInspectionConfigurationArn are independent optional keys in the schema.
violation contains make_diag_full("pf-networkfirewall-policy-session-holding-requires-tls", "ERROR", name,
	"Properties.FirewallPolicy.EnableTLSSessionHolding",
	"EnableTLSSessionHolding is true but the policy has no TLSInspectionConfigurationArn; CreateFirewallPolicy answers \"TLSInspectionConfigurationArn value is required when EnableTLSSessionHolding is true.\"",
	"Point TLSInspectionConfigurationArn at a TLS inspection configuration, or drop EnableTLSSessionHolding",
	"https://docs.aws.amazon.com/network-firewall/latest/APIReference/API_FirewallPolicy.html") if {
	some name in resources_of_type("AWS::NetworkFirewall::FirewallPolicy")
	object.get(_pf_nfwlib_fp(name), "EnableTLSSessionHolding", false) == true
	object.get(_pf_nfwlib_fp(name), "TLSInspectionConfigurationArn", "__pf_absent") == "__pf_absent"
}
