package cdk_preflight

import rego.v1

# Same fixed allowlist as EmailConfiguration.SourceArn, not the deploy region.

violation contains make_diag_full("pf-cognito-risk-notify-source-arn-region", "ERROR", name,
	"Properties.AccountTakeoverRiskConfiguration.NotifyConfiguration.SourceArn",
	sprintf("NotifyConfiguration.SourceArn is in %v; the risk configuration call fails with \"Provided SourceArn must be in one of the following SES regions: eu-west-1, us-east-1, us-west-2.\"", [r]),
	"Use a SES identity in eu-west-1, us-east-1 or us-west-2",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolriskconfigurationattachment.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolRiskConfigurationAttachment")
	arn := _pf_coglib_g3(name, "AccountTakeoverRiskConfiguration", "NotifyConfiguration", "SourceArn")
	r := _pf_coglib_arn_region(arn)
	not r in _pf_coglib_ses_regions
}
