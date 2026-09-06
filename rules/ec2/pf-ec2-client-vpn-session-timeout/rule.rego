package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ec2-client-vpn-session-timeout", "ERROR", name,
	"Properties.SessionTimeoutHours",
	sprintf("SessionTimeoutHours %v is not accepted (\"Session Timeout you provided is not valid; valid values are [8, 10, 12, 24]\")", [n]),
	"Use 8, 10, 12 or 24",
	"https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateClientVpnEndpoint.html") if {
	some name in resources_of_type("AWS::EC2::ClientVpnEndpoint")
	n := to_number(resolve(name, "Properties.SessionTimeoutHours"))
	not n in {8, 10, 12, 24}
}
