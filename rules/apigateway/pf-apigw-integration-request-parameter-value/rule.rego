package cdk_preflight

import rego.v1

# A static value has to be single-quoted; anything unquoted is read as a
# mapping expression.
_pf_apgirpv_ok(v) if startswith(v, "'")

_pf_apgirpv_ok(v) if regex.match(`^(method\.request\.|context\.|stageVariables\.)`, v)

violation contains make_diag_full("pf-apigw-integration-request-parameter-value", "ERROR", name,
	sprintf("Properties.Integration.RequestParameters.%s", [k]),
	sprintf("Integration.RequestParameters value '%s' is neither a quoted static value nor a mapping expression; the method create fails with \"Invalid mapping expression specified\"", [v]),
	sprintf("Write a static value as \"'%s'\", or use method.request.* / context.* / stageVariables.*", [v]),
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-method-integration.html") if {
	some name in resources_of_type("AWS::ApiGateway::Method")
	rp := resolve(name, "Properties.Integration.RequestParameters")
	is_object(rp)
	some k, v in rp
	is_string(v)
	not _pf_apgirpv_ok(v)
}
