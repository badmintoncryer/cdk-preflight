package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigw-integration-credentials-arn", "ERROR", name,
	"Properties.Integration.Credentials",
	sprintf("Integration.Credentials '%s' is not an ARN; the method create fails with \"Invalid ARN specified in the request\"", [c]),
	"Use the IAM role ARN to assume (or arn:aws:iam::*:user/* to pass the caller's credentials)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-method-integration.html") if {
	some name in resources_of_type("AWS::ApiGateway::Method")
	c := resolve(name, "Properties.Integration.Credentials")
	is_string(c)
	not input.resources[c]
	not startswith(c, "arn:")
}
