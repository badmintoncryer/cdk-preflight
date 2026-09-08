package cdk_preflight

import rego.v1

_pf_ec2dho_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-dhcpoptions.html"

_pf_ec2dho_keys := ["DomainName", "DomainNameServers", "NtpServers", "NetbiosNameServers", "NetbiosNodeType", "Ipv6AddressPreferredLeaseTime"]

_pf_ec2dho_set(name) if {
	some k in _pf_ec2dho_keys
	not _pf_ec2lib_absent(name, k)
}

violation contains make_diag_full("pf-ec2-dhcp-options-empty", "ERROR", name,
	"Properties",
	"A DHCP options set configures nothing (\"The request must contain the parameter dhcpConfigurations\")",
	"Set at least one of DomainName, DomainNameServers, NtpServers, NetbiosNameServers or NetbiosNodeType",
	_pf_ec2dho_url) if {
	some name in resources_of_type("AWS::EC2::DHCPOptions")
	not _pf_ec2dho_set(name)
}
