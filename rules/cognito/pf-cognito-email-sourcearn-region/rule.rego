package cdk_preflight

import rego.v1

# Not "the deploy region": the service takes a fixed allowlist of three SES
# regions regardless of where the pool lives (measured 2026-09-08).

violation contains make_diag_full("pf-cognito-email-sourcearn-region", "ERROR", name,
	"Properties.EmailConfiguration.SourceArn",
	sprintf("EmailConfiguration.SourceArn is in %v; the pool create fails with \"Provided SourceArn must be in one of the following SES regions: eu-west-1, us-east-1, us-west-2.\"", [r]),
	"Use a SES identity in eu-west-1, us-east-1 or us-west-2",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	arn := resolve(name, "Properties.EmailConfiguration.SourceArn")
	r := _pf_coglib_arn_region(arn)
	not r in _pf_coglib_ses_regions
}
