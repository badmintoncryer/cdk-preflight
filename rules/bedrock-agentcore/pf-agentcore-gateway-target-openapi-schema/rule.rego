package cdk_preflight

import rego.v1

# The InlinePayload is an opaque string to the schema. The service parses it
# after CreateGatewayTarget returns, so a bad document surfaces as a target in
# status FAILED and a NotStabilized rollback. Three checks measured to fail:
# no top-level `openapi` (Swagger 2.0), no `servers`, an operation without
# `operationId`. Non-JSON payloads are left alone (YAML is not measured).
_pf_gwtoapi_doc(name) := doc if {
	s := resolve(name, "Properties.TargetConfiguration.Mcp.OpenApiSchema.InlinePayload")
	is_string(s)
	doc := json.unmarshal(s)
	is_object(doc)
}

_pf_gwtoapi_url := "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-building-adding-targets-openapi.html"
_pf_gwtoapi_path := "Properties.TargetConfiguration.Mcp.OpenApiSchema.InlinePayload"
_pf_gwtoapi_methods := {"get", "put", "post", "delete", "options", "head", "patch", "trace"}

violation contains make_diag_full("pf-agentcore-gateway-target-openapi-schema", "ERROR", name, _pf_gwtoapi_path,
	"The inline OpenAPI document has no top-level `openapi` field (Swagger 2.0 is not accepted); the target fails to stabilize with \"Invalid OpenAPI schema: attribute openapi is missing\"",
	"Convert the document to OpenAPI 3.x (`openapi: 3.0.x`)", _pf_gwtoapi_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayTarget")
	doc := _pf_gwtoapi_doc(name)
	not is_string(object.get(doc, "openapi", null))
}

violation contains make_diag_full("pf-agentcore-gateway-target-openapi-schema", "ERROR", name, _pf_gwtoapi_path,
	"The inline OpenAPI document has no `servers` entry; the target fails to stabilize with \"Server URL must not be empty\"",
	"Add a `servers` list with the HTTPS base URL of the API", _pf_gwtoapi_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayTarget")
	doc := _pf_gwtoapi_doc(name)
	is_string(object.get(doc, "openapi", null))
	servers := object.get(doc, "servers", [])
	count(servers) == 0
}

violation contains make_diag_full("pf-agentcore-gateway-target-openapi-schema", "ERROR", name, _pf_gwtoapi_path,
	sprintf("Operation %s %s has no operationId; the target fails to stabilize with \"Operation %s -> %s must have an operationId\"", [upper(method), path, path, upper(method)]),
	"Give every operation a unique operationId (it becomes the tool name)", _pf_gwtoapi_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayTarget")
	doc := _pf_gwtoapi_doc(name)
	is_string(object.get(doc, "openapi", null))
	paths := object.get(doc, "paths", {})
	some path, item in paths
	is_object(item)
	some method, op in item
	method in _pf_gwtoapi_methods
	is_object(op)
	not is_string(object.get(op, "operationId", null))
}
