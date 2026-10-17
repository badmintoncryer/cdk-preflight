package cdk_preflight

import rego.v1

# pf-apigw-lambda-integration-post for an API defined by its OpenAPI Body: an
# x-amazon-apigateway-integration that calls a Lambda function with any
# httpMethod but POST is imported as is, and then every request returns 500.
_pf_apblp_text(v) := v if is_string(v)

_pf_apblp_text(v) := t if {
	is_object(v)
	t := object.get(v, "__dynamic", null)
	is_string(t)
}

violation contains make_diag_full("pf-apigw-body-lambda-integration-post", "ERROR", name,
	sprintf("Properties.Body.paths.%s.%s.x-amazon-apigateway-integration.httpMethod", [p, verb]),
	sprintf("%s %s calls a Lambda function with httpMethod '%s'; the Lambda Invoke API only takes POST, so every request to it returns 500 (the Lambda endpoint answers AccessDeniedException)", [upper(verb), p, m]),
	"Set httpMethod to POST in the x-amazon-apigateway-integration (the operation's own method can stay as it is)",
	"https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-swagger-extensions-integration.html") if {
	some name in resources_of_type("AWS::ApiGateway::RestApi")
	props := input.resources[name].properties
	is_object(props)
	body := object.get(props, "Body", null)
	is_object(body)
	paths := object.get(body, "paths", null)
	is_object(paths)
	some p, item in paths
	is_object(item)
	some verb, op in item
	is_object(op)
	integ := object.get(op, "x-amazon-apigateway-integration", null)
	is_object(integ)
	t := object.get(integ, "type", null)
	is_string(t)
	lower(t) in {"aws", "aws_proxy"}
	m := object.get(integ, "httpMethod", null)
	is_string(m)
	upper(m) != "POST"
	uri := _pf_apblp_text(object.get(integ, "uri", null))
	contains(uri, ":lambda:path/2015-03-31/functions/")
	# Invoke だけが POST 専用。GetFunctionConfiguration などの管理 API への GET は正しい
	endswith(uri, "/invocations")
}
