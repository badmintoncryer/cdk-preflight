package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-ns-code-handlers-s3-exclusive", "ERROR", name,
	"Properties.CodeS3Location",
	"both CodeHandlers and CodeS3Location are set; the namespace create rejects two sources for the same handler code",
	"Keep either CodeHandlers or CodeS3Location",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-channelnamespace.html") if {
	some name in resources_of_type("AWS::AppSync::ChannelNamespace")
	is_string(resolve(name, "Properties.CodeHandlers"))
	is_string(resolve(name, "Properties.CodeS3Location"))
}
