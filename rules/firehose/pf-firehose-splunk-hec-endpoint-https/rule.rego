package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-splunk-hec-endpoint-https", "ERROR", name,
	"Properties.SplunkDestinationConfiguration.HECEndpoint",
	sprintf("HECEndpoint '%s' is not an HTTPS URL; the stream create fails with \"Invalid HECEndpoint. Supported endpoint format is https://<domain>:<port>.\"", [u]),
	"Write the endpoint as https://<domain>:<port>",
	"https://docs.aws.amazon.com/firehose/latest/dev/create-destination.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path == "Properties.SplunkDestinationConfiguration"
	u := object.get(c, "HECEndpoint", null)
	_pf_fhlib_lit(u)
	not startswith(u, "https://")
}
