package cdk_preflight

import rego.v1

# An AWS integration URI is an API Gateway ARN wrapping the target action, not
# the target's own ARN - a distinction that lives inside the string.
violation contains make_diag_full("pf-apigw-integration-aws-uri", "ERROR", name,
	"Properties.Integration.Uri",
	sprintf("Integration.Uri '%s' is not an API Gateway integration ARN; the method create fails with \"AWS ARN for integration must contain path or action\"", [uri]),
	"Use arn:<partition>:apigateway:<region>:<service>:path/... (Lambda: .../lambda:path/2015-03-31/functions/<function arn>/invocations)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-method-integration.html") if {
	some name in resources_of_type("AWS::ApiGateway::Method")
	resolve(name, "Properties.Integration.Type") in {"AWS", "AWS_PROXY"}
	uri := resolve(name, "Properties.Integration.Uri")
	is_string(uri)
	startswith(uri, "arn:")
	not regex.match(`^arn:[^:]*:apigateway:[^:]*:[^:]*:(path|action)/`, uri)
}
