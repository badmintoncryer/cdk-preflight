package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-http-buffer-size", "ERROR", name,
	"Properties.HttpEndpointDestinationConfiguration.BufferingHints.SizeInMBs",
	sprintf("SizeInMBs is %v; the stream create fails with \"failed to satisfy constraint: Member must have value less than or equal to 64\"", [v]),
	"Set SizeInMBs between 1 and 64 for an HTTP endpoint destination",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_HttpEndpointBufferingHints.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path == "Properties.HttpEndpointDestinationConfiguration"
	raw := object.get(object.get(c, "BufferingHints", {}), "SizeInMBs", null)
	raw != null
	v := to_number(raw)
	_pf_fhhbs_out(v)
}

_pf_fhhbs_out(v) if v < 1

_pf_fhhbs_out(v) if v > 64
