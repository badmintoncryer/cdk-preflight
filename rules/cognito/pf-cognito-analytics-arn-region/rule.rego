package cdk_preflight

import rego.v1

# The service reports it as an unsupported region rather than a mismatch:
# "The integration with Pinpoint is not supported for the requested <region>
# region." data.cdk_preflight.deploy_region is injected only in enforce mode.

violation contains make_diag_full("pf-cognito-analytics-arn-region", "ERROR", name,
	"Properties.AnalyticsConfiguration.ApplicationArn",
	sprintf("the Pinpoint project is in '%v' but the client deploys to '%v'; the client create fails with \"The integration with Pinpoint is not supported for the requested %v region.\"", [r, region, r]),
	"Use a Pinpoint project in the pool's own region",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	r := _pf_coglib_arn_region(resolve(name, "Properties.AnalyticsConfiguration.ApplicationArn"))
	r != region
}
