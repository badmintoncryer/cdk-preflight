package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-transfer-sftp-port-range", "ERROR", name,
	"Properties.ProtocolDetails.SftpPorts",
	sprintf("SftpPort %v; the server create fails with \"Invalid port value\" (allowed: 22 or 2000-65535)", [p]),
	"Use port 22 or a port from 2000 to 65535",
	"https://docs.aws.amazon.com/transfer/latest/APIReference/API_ProtocolDetails.html") if {
	some name in resources_of_type("AWS::Transfer::Server")
	some it in flatten_list(name, "Properties.ProtocolDetails.SftpPorts")
	is_object(it.value)
	p := it.value.SftpPort
	is_number(p)
	_pf_xsp_bad(p)
}

_pf_xsp_bad(p) if {
	p != 22
	p < 2000
}

