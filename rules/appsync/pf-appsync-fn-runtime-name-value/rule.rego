package cdk_preflight

import rego.v1

# The engine knows this allowed-value list but reports it as W3030 (WARN),
# which never blocks a deploy; see AGENTS.md on the gray zone.
violation contains make_diag_full("pf-appsync-fn-runtime-name-value", "ERROR", name,
	"Properties.Runtime.Name",
	sprintf("Runtime.Name '%s' is not APPSYNC_JS; the function create rejects the value", [v]),
	"Use APPSYNC_JS",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-functionconfiguration.html") if {
	some name in resources_of_type("AWS::AppSync::FunctionConfiguration")
	v := resolve(name, "Properties.Runtime.Name")
	is_string(v)
	not v in {"APPSYNC_JS"}
}
