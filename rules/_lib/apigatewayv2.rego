package cdk_preflight

import rego.v1

# Protocol of the Api a child resource points at ("HTTP" or "WEBSOCKET").
# Undefined when ApiId is an imported id, so callers skip imported APIs. Half
# of the ApiGatewayV2 constraints are protocol-dependent, which is why this is
# a lib rather than a per-rule helper.
_pf_apigwv2lib_protocol(name) := p if {
	api := resolve(name, "Properties.ApiId")
	api in resources_of_type("AWS::ApiGatewayV2::Api")
	p := resolve(api, "Properties.ProtocolType")
}
