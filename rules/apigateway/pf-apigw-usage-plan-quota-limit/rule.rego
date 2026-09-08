package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigw-usage-plan-quota-limit", "ERROR", name,
	"Properties.Quota.Limit",
	sprintf("Quota.Limit is %v; the usage plan create fails with \"Usage Plan quota limit must be a non-negative numeric\"", [l]),
	"Use a quota limit of 1 or more, or drop Quota entirely",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-apigateway-usageplan-quotasettings.html") if {
	some name in resources_of_type("AWS::ApiGateway::UsagePlan")
	l := to_number(resolve(name, "Properties.Quota.Limit"))
	l < 1
}
