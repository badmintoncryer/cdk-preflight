package cdk_preflight

import rego.v1

# The value charset is pf-apigw-stage-variable-value; this is the key.
violation contains make_diag_full("pf-apigw-stage-variable-name", "ERROR", name,
	sprintf("Properties.Variables.%s", [k]),
	sprintf("Stage variable name '%s' has characters outside word characters; the stage create fails with \"Invalid stage variable name: %s. Please use names with only word characters.\"", [k, k]),
	"Use only letters, digits and underscores in the variable name",
	"https://docs.aws.amazon.com/apigateway/latest/developerguide/stage-variables.html") if {
	some name in resources_of_type("AWS::ApiGateway::Stage")
	vars := resolve(name, "Properties.Variables")
	is_object(vars)
	some k, _ in vars
	not regex.match(`^[a-zA-Z0-9_]+$`, k)
}
