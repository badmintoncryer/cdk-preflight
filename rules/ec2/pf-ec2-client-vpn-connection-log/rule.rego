package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ec2-client-vpn-connection-log", "ERROR", name,
	"Properties.ConnectionLogOptions.CloudwatchLogGroup",
	"ConnectionLogOptions.Enabled is true but no CloudwatchLogGroup is set (\"Please provide a cloudwatch log group\")",
	"Set ConnectionLogOptions.CloudwatchLogGroup, or turn connection logging off",
	"https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateClientVpnEndpoint.html") if {
	some name in resources_of_type("AWS::EC2::ClientVpnEndpoint")
	opts := resolve(name, "Properties.ConnectionLogOptions")
	is_object(opts)
	object.get(opts, "Enabled", false) == true
	object.get(opts, "CloudwatchLogGroup", "__pf_absent") == "__pf_absent"
}
