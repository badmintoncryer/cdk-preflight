package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ec2-client-vpn-port", "ERROR", name,
	"Properties.VpnPort",
	sprintf("VpnPort %v is not accepted (\"Vpn port you provided is not valid; valid values are [443, 1194]\")", [n]),
	"Use 443 or 1194",
	"https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateClientVpnEndpoint.html") if {
	some name in resources_of_type("AWS::EC2::ClientVpnEndpoint")
	n := to_number(resolve(name, "Properties.VpnPort"))
	not n in {443, 1194}
}
