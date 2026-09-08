package cdk_preflight

import rego.v1

# Destination is "<action>:<target>" - parameter mapping's own DSL, carried in
# CloudFormation as {"<status>": {"ResponseParameters": [{Destination, Source}]}}.
_pf_agvrpa_ok(d) if regex.match(`^(append|overwrite|remove):(header\.[^ ]+|statuscode)$`, d)

violation contains make_diag_full("pf-apigwv2-response-parameter-action", "ERROR", name,
	sprintf("Properties.ResponseParameters.%s", [sc]),
	sprintf("Response parameter destination '%s' is not \"<append|overwrite|remove>:<header.name|statuscode>\"; the integration create fails with \"Invalid Response Actioned Parameter destination specified: %s\"", [d, d]),
	"Use destinations like overwrite:header.Location or overwrite:statuscode",
	"https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-parameter-mapping.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Integration")
	rp := resolve(name, "Properties.ResponseParameters")
	is_object(rp)
	some sc, entry in rp
	is_object(entry)
	some m in entry.ResponseParameters
	is_object(m)
	d := m.Destination
	is_string(d)
	not _pf_agvrpa_ok(d)
}
