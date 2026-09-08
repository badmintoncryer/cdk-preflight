package cdk_preflight

import rego.v1

_pf_ec2vgex_url := "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateVpnConnection.html"

violation contains make_diag_full("pf-ec2-vpn-gateway-exclusive", "ERROR", name,
	"Properties.TransitGatewayId",
	"A VPN connection names both VpnGatewayId and TransitGatewayId (\"The request must not contain both parameter vpnGatewayId and transitGatewayId\")",
	"Keep VpnGatewayId for a virtual private gateway or TransitGatewayId for a transit gateway, not both",
	_pf_ec2vgex_url) if {
	some name in resources_of_type("AWS::EC2::VPNConnection")
	not _pf_ec2lib_absent(name, "VpnGatewayId")
	not _pf_ec2lib_absent(name, "TransitGatewayId")
}
