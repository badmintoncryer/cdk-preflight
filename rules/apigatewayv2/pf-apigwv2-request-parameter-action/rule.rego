package cdk_preflight

import rego.v1

# Only for proxy integrations: with an IntegrationSubtype the same property
# holds the service API's own parameter names.
_pf_agvqpa_no_subtype(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "IntegrationSubtype", "__pf_absent") == "__pf_absent"
}

_pf_agvqpa_ok(k) if regex.match(`^(append|overwrite|remove):(header|querystring|path)\.[^ ]+$`, k)

violation contains make_diag_full("pf-apigwv2-request-parameter-action", "ERROR", name,
	"Properties.RequestParameters",
	sprintf("Request parameter mapping '%s' is not \"<append|overwrite|remove>:<header|querystring|path>.<name>\"; the integration create fails with \"Invalid Request Actioned Parameter\"", [k]),
	"Use keys like overwrite:header.X-Api or append:querystring.q",
	"https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-parameter-mapping.html") if {
	some name in resources_of_type("AWS::ApiGatewayV2::Integration")
	_pf_agvqpa_no_subtype(name)
	rp := resolve(name, "Properties.RequestParameters")
	is_object(rp)
	some k, _ in rp
	not _pf_agvqpa_ok(k)
}
