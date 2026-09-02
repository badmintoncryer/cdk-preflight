package cdk_preflight

import rego.v1

# Allowed per the service error itself: alphanumerics plus space and
# - . _ : / ? & = , (note: space IS legal).
_pf_apgsvv_ok(v) if regex.match(`^[a-zA-Z0-9 ._:/?&=,-]*$`, v)

violation contains make_diag_full("pf-apigw-stage-variable-value", "ERROR", name,
	sprintf("Properties.Variables.%s", [k]),
	sprintf("Stage variable '%s' has characters outside the allowed set; the stage create fails with \"Invalid stage variable value of key %s.  Please use values with alphanumeric characters and the symbols ' ', -', '.', '_', ':', '/', '?', '&', '=', and ','.\"", [k, k]),
	"Restrict the value to alphanumerics and ' ', -, ., _, :, /, ?, &, =, ,",
	"https://docs.aws.amazon.com/apigateway/latest/developerguide/stage-variables.html") if {
	some name in resources_of_type("AWS::ApiGateway::Stage")
	vars := resolve(name, "Properties.Variables")
	is_object(vars)
	some k, v in vars
	is_string(v)
	not _pf_apgsvv_ok(v)
}
