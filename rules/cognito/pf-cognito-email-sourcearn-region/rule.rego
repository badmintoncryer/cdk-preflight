package cdk_preflight

import rego.v1

# The allowed SES Regions depend on the pool's Region; the table and its
# measurements live in _lib/cognito.rego (_pf_coglib_ses_region_bad, issue #395).

violation contains make_diag_full("pf-cognito-email-sourcearn-region", "ERROR", name,
	"Properties.EmailConfiguration.SourceArn",
	sprintf("EmailConfiguration.SourceArn is in %v, which a user pool in %v cannot use; the pool create fails with \"Invalid EmailConfiguration.SourceArn. Provided SourceArn must be in ...\" (the allowed SES Regions depend on the pool's Region)", [r, dr]),
	"Use a SES identity in the pool's own Region; pools in the backwards compatible Regions (such as ap-northeast-1) may also use eu-west-1, us-east-1 or us-west-2",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	arn := resolve(name, "Properties.EmailConfiguration.SourceArn")
	r := _pf_coglib_arn_region(arn)
	_pf_coglib_ses_region_bad(r)
	dr := data.cdk_preflight.deploy_region
}
