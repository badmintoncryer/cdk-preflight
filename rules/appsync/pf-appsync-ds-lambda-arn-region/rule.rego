package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-ds-lambda-arn-region", "ERROR", name,
	"Properties.LambdaConfig.LambdaFunctionArn",
	sprintf("the Lambda function is in region '%s' but this stack deploys to '%s'; the data source create fails because AppSync only invokes a function in its own region", [parts[3], region]),
	"Use a Lambda function in the region this stack deploys to",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-datasource.html") if {
	some name in resources_of_type("AWS::AppSync::DataSource")
	region := data.cdk_preflight.deploy_region
	arn := resolve(name, "Properties.LambdaConfig.LambdaFunctionArn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) > 3
	parts[2] == "lambda"
	parts[3] != region
}
