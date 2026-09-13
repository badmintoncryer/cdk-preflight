package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-res-runtime-version-value", "ERROR", name,
	"Properties.Runtime.RuntimeVersion",
	sprintf("RuntimeVersion '%s' does not exist; the resolver create fails because APPSYNC_JS only has version 1.0.0", [v]),
	"Use RuntimeVersion: 1.0.0",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-resolver.html") if {
	some name in resources_of_type("AWS::AppSync::Resolver")
	resolve(name, "Properties.Runtime.Name") == "APPSYNC_JS"
	v := resolve(name, "Properties.Runtime.RuntimeVersion")
	is_string(v)
	v != "1.0.0"
}
