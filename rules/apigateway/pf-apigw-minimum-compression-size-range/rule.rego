package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigw-minimum-compression-size-range", "ERROR", name,
	"Properties.MinimumCompressionSize",
	sprintf("MinimumCompressionSize %v is outside 0-10485760; the API create fails with \"Invalid minimum compression size, must be between 0 and 10485760\"", [s]),
	"Use a compression threshold between 0 and 10485760 bytes",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-restapi.html") if {
	some name in resources_of_type("AWS::ApiGateway::RestApi")
	s := to_number(resolve(name, "Properties.MinimumCompressionSize"))
	s > 10485760
}
