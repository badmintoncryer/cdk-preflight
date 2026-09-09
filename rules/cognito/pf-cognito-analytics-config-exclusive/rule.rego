package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-analytics-config-exclusive", "ERROR", name,
	sprintf("Properties.AnalyticsConfiguration.%s", [k]),
	sprintf("AnalyticsConfiguration has both ApplicationArn and %s; the client create fails with \"Invalid analytics configuration given, either <application arn> or <application id, role arn, external id> are valid\"", [k]),
	"Use either ApplicationArn alone, or ApplicationId with RoleArn and ExternalId",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	_pf_coglib_set(_pf_coglib_g2(name, "AnalyticsConfiguration", "ApplicationArn"))
	some k in ["ApplicationId", "RoleArn", "ExternalId"]
	_pf_coglib_set(_pf_coglib_g2(name, "AnalyticsConfiguration", k))
}
