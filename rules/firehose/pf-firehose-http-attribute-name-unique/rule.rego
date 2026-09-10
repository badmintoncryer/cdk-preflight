package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-http-attribute-name-unique", "ERROR", name,
	"Properties.HttpEndpointDestinationConfiguration.RequestConfiguration.CommonAttributes",
	sprintf("%d common attributes are declared but only %d distinct names; the stream create fails with \"Http Endpoint Common Attributes have duplicate name ...\"", [n, u]),
	"Give every common attribute a distinct AttributeName",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_HttpEndpointCommonAttribute.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path == "Properties.HttpEndpointDestinationConfiguration"
	attrs := object.get(object.get(c, "RequestConfiguration", {}), "CommonAttributes", null)
	is_array(attrs)
	names := [x | some a in attrs; is_object(a); x := object.get(a, "AttributeName", null); is_string(x)]
	n := count(names)
	u := count({x | some x in names})
	u < n
}
