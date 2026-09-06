package cdk_preflight

import rego.v1

_pf_cvpncidr_out(p) if p < 12

_pf_cvpncidr_out(p) if p > 22

violation contains make_diag_full("pf-ec2-client-vpn-cidr-size", "ERROR", name,
	"Properties.ClientCidrBlock",
	sprintf("ClientCidrBlock '%s' has netmask /%v; a Client VPN endpoint requires /12 through /22 (\"Client cidr block must be of size /12 or smaller\")", [c, p]),
	"Use a netmask between /12 and /22",
	"https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateClientVpnEndpoint.html") if {
	some name in resources_of_type("AWS::EC2::ClientVpnEndpoint")
	c := resolve(name, "Properties.ClientCidrBlock")
	is_string(c)
	regex.match(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$`, c)
	p := to_number(split(c, "/")[1])
	_pf_cvpncidr_out(p)
}
