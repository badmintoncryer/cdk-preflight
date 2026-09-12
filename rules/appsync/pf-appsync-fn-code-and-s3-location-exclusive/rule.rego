package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-fn-code-and-s3-location-exclusive", "ERROR", name,
	"Properties.CodeS3Location",
	"both Code and CodeS3Location are set; the function create rejects two sources for the same handler",
	"Keep either Code or CodeS3Location",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-functionconfiguration.html") if {
	some name in resources_of_type("AWS::AppSync::FunctionConfiguration")
	is_string(resolve(name, "Properties.Code"))
	is_string(resolve(name, "Properties.CodeS3Location"))
}
