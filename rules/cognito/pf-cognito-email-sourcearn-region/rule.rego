package cdk_preflight

import rego.v1

# Which SES Regions a user pool may send from depends on the pool's own Region
# (Cognito developer guide, "Amazon SES email configuration Regions"): its own
# Region, plus eu-west-1 / us-east-1 / us-west-2 for the "Backwards compatible"
# pools, or the listed remote Regions for the "Alternate Region" pools. The bench
# reproduced the error with a us-east-1 pool and an ap-northeast-1 identity.
#
# The rule only narrows the old fixed three-Region check (issue #395): it stays
# silent when the deploy Region is unknown or missing from the guide's table, on
# an identity in the pool's own Region or a listed alternate Region, and on a
# wildcard Region (arn:aws:ses:*:...), which the guide documents.

_pf_cgesr_pool_regions := {
	"af-south-1", "ap-east-1", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
	"ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3",
	"ap-southeast-4", "ap-southeast-5", "ap-southeast-7", "ca-central-1", "ca-west-1",
	"eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2",
	"eu-west-1", "eu-west-2", "eu-west-3", "il-central-1", "me-central-1",
	"me-south-1", "mx-central-1", "sa-east-1", "us-east-1", "us-east-2",
	"us-west-1", "us-west-2",
}

_pf_cgesr_alternates := {
	"ap-east-1": {"ap-southeast-1", "ap-northeast-1"},
	"ap-south-2": {"ap-south-1", "ap-southeast-1"},
	"ap-southeast-4": {"ap-southeast-2", "ap-southeast-1"},
	"ap-southeast-5": {"ap-southeast-2", "ap-southeast-1"},
	"ap-southeast-7": {"ap-southeast-1", "ap-south-1"},
	"ca-west-1": {"ca-central-1", "us-west-1"},
	"eu-central-2": {"eu-central-1", "eu-west-2"},
	"eu-south-2": {"eu-west-3", "eu-north-1"},
	"me-central-1": {"eu-central-1", "eu-west-2"},
	"mx-central-1": {"us-east-1", "us-west-2"},
}

violation contains make_diag_full("pf-cognito-email-sourcearn-region", "ERROR", name,
	"Properties.EmailConfiguration.SourceArn",
	sprintf("EmailConfiguration.SourceArn is in %v, which a user pool in %v cannot send from; the pool create fails with \"Provided SourceArn must be in one of the following SES regions\"", [r, dr]),
	"Use a SES identity in the pool's own Region, or in a Region the Cognito developer guide lists for the pool's Region",
	"https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-email.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	dr := data.cdk_preflight.deploy_region
	dr in _pf_cgesr_pool_regions
	arn := resolve(name, "Properties.EmailConfiguration.SourceArn")
	r := _pf_coglib_arn_region(arn)
	r != dr
	r != "*"
	not r in _pf_coglib_ses_regions
	not r in object.get(_pf_cgesr_alternates, dr, set())
}
