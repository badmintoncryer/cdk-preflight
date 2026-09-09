package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-analytics-application-requires-role", "ERROR", name,
	"Properties.AnalyticsConfiguration.RoleArn",
	"AnalyticsConfiguration.ApplicationId is set without a RoleArn; the client create fails with \"Invalid analytics configuration given, either <application arn> or <application id, role arn, external id> are valid\"",
	"Add AnalyticsConfiguration.RoleArn (and ExternalId), or use ApplicationArn",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	_pf_coglib_set(_pf_coglib_g2(name, "AnalyticsConfiguration", "ApplicationId"))
	_pf_coglib_absent(_pf_coglib_g2(name, "AnalyticsConfiguration", "RoleArn"))
}
