package cdk_preflight

import rego.v1

# The engine knows this allowed-value list but reports it as W3030 (WARN),
# which never blocks a deploy; see AGENTS.md on the gray zone.
violation contains make_diag_full("pf-appsync-res-kind-value", "ERROR", name,
	"Properties.Kind",
	sprintf("Kind '%s' is not UNIT or PIPELINE; the resolver create rejects the value", [v]),
	"Use UNIT or PIPELINE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-resolver.html") if {
	some name in resources_of_type("AWS::AppSync::Resolver")
	v := resolve(name, "Properties.Kind")
	is_string(v)
	not v in {"UNIT", "PIPELINE"}
}
