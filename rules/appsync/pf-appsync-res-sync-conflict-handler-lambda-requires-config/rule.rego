package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-res-sync-conflict-handler-lambda-requires-config", "ERROR", name,
	"Properties.SyncConfig.LambdaConflictHandlerConfig",
	"SyncConfig.ConflictHandler is LAMBDA but LambdaConflictHandlerConfig is not set; the resolver create fails because there is no function to resolve conflicts with",
	"Set SyncConfig.LambdaConflictHandlerConfig, or use a different ConflictHandler",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-resolver.html") if {
	some name in resources_of_type("AWS::AppSync::Resolver")
	sc := resolve(name, "Properties.SyncConfig")
	is_object(sc)
	sc.ConflictHandler == "LAMBDA"
	object.get(sc, "LambdaConflictHandlerConfig", "__pf_absent") == "__pf_absent"
}
