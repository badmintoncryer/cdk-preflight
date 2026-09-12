package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-ns-handler-lambda-requires-config", "ERROR", name,
	"Properties.HandlerConfigs",
	sprintf("HandlerConfigs.%s.Behavior is DIRECT but its Integration has no LambdaConfig; the namespace create fails because a direct integration is invoked as a Lambda function", [k]),
	"Set Integration.LambdaConfig, or use Behavior: CODE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-channelnamespace.html") if {
	some name in resources_of_type("AWS::AppSync::ChannelNamespace")
	hc := resolve(name, "Properties.HandlerConfigs")
	is_object(hc)
	some k, h in hc
	h.Behavior == "DIRECT"
	object.get(h.Integration, "LambdaConfig", "__pf_absent") == "__pf_absent"
}
