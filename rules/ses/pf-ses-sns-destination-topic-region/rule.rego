package cdk_preflight

import rego.v1

# SES は自分のリージョンのトピックにしか publish できない。スキーマの pattern は
# リージョンを `[a-z0-9-]+` で通すだけで、デプロイ先との一致を見ない。
violation contains make_diag_full("pf-ses-sns-destination-topic-region", "ERROR", name,
	"Properties.EventDestination.SnsDestination.TopicARN",
	sprintf("the SNS topic is in '%v' but the event destination deploys to '%v'; the event destination create fails with \"SNS topic must be located in same region as SES <%v>\"", [tr, region, region]),
	"Publish the events to an SNS topic in the deployment Region",
	"https://docs.aws.amazon.com/ses/latest/dg/regions.html") if {
	some name in resources_of_type("AWS::SES::ConfigurationSetEventDestination")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	arn := resolve(name, "Properties.EventDestination.SnsDestination.TopicARN")
	_pf_ses_lit(arn)
	tr := _pf_ses_arn_region(arn)
	tr != region
}
