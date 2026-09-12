package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-res-code-and-s3-location-exclusive", "ERROR", name,
	"Properties.CodeS3Location",
	"both Code and CodeS3Location are set; the resolver create rejects two sources for the same handler",
	"Keep either Code or CodeS3Location",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-resolver.html") if {
	some name in resources_of_type("AWS::AppSync::Resolver")
	is_string(resolve(name, "Properties.Code"))
	is_string(resolve(name, "Properties.CodeS3Location"))
}
