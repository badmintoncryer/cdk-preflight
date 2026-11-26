package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-transfer-sftp-ports-public-only", "ERROR", name,
	"Properties.ProtocolDetails.SftpPorts",
	sprintf("SftpPorts with EndpointType %v; the server create fails with \"SFTP custom ports unsupported for EndpointType\"", [et]),
	"Drop SftpPorts, or use EndpointType PUBLIC",
	"https://docs.aws.amazon.com/transfer/latest/APIReference/API_ProtocolDetails.html") if {
	some name in resources_of_type("AWS::Transfer::Server")
	count(flatten_list(name, "Properties.ProtocolDetails.SftpPorts")) > 0
	et := resolve(name, "Properties.EndpointType")
	is_string(et)
	not input.resources[et]
	upper(et) != "PUBLIC"
}
