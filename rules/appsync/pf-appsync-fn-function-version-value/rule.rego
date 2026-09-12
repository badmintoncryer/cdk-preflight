package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-fn-function-version-value", "ERROR", name,
	"Properties.FunctionVersion",
	sprintf("FunctionVersion '%s' does not exist; the function create fails because the only version is 2018-05-29", [v]),
	"Use FunctionVersion: 2018-05-29",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-functionconfiguration.html") if {
	some name in resources_of_type("AWS::AppSync::FunctionConfiguration")
	v := resolve(name, "Properties.FunctionVersion")
	is_string(v)
	v != "2018-05-29"
}
