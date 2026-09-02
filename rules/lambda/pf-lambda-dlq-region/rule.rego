package cdk_preflight

import rego.v1

# Region comparison needs the deploy region, which only this pack sees
# (data.cdk_preflight.deploy_region is defined in enforce mode; the rule
# skips without it).
violation contains make_diag_full("pf-lambda-dlq-region", "ERROR", name,
	"Properties.DeadLetterConfig.TargetArn",
	sprintf("Dead letter target region '%s' is not the deploy region '%s'; the function create fails with \"Invalid dead letter queue ARN: The resource specified by the TargetArn must be in the same region as the Lambda function it's associated with.\"", [parts[3], region]),
	"Point DeadLetterConfig at a queue or topic in the same region",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-function-deadletterconfig.html") if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::Lambda::Function")
	arn := resolve(name, "Properties.DeadLetterConfig.TargetArn")
	is_string(arn)
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) >= 6
	parts[3] != region
}
