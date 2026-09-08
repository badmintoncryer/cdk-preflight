package cdk_preflight

import rego.v1

_pf_ec2dhn_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-dhcpoptions.html"

_pf_ec2dhn_lists := ["NtpServers", "DomainNameServers", "NetbiosNameServers"]

violation contains make_diag_full("pf-ec2-dhcp-ntp-servers-count", "ERROR", name,
	sprintf("Properties.%s", [k]),
	sprintf("%s has %v entries; a DHCP option value takes at most four (\"Invalid DHCP option value\")", [k, n]),
	"Keep at most four addresses per option",
	_pf_ec2dhn_url) if {
	some name in resources_of_type("AWS::EC2::DHCPOptions")
	some k in _pf_ec2dhn_lists
	n := count(flatten_list(name, sprintf("Properties.%s", [k])))
	n > 4
}
