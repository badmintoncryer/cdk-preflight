package cdk_preflight

import rego.v1

# SES は自分のリージョンの配信ストリームにしか書けない。リージョン検査はロールの
# assume 検査と存在検査より先に走るので、偽 ARN でもリージョンを名指しして落ちる。
violation contains make_diag_full("pf-ses-firehose-destination-stream-region", "ERROR", name,
	"Properties.EventDestination.KinesisFirehoseDestination.DeliveryStreamARN",
	sprintf("the delivery stream is in '%v' but the event destination deploys to '%v'; the event destination create fails with \"Delivery stream <...> must be located in same region as SES <%v>\"", [sr, region, region]),
	"Stream the events to a Firehose delivery stream in the deployment Region",
	"https://docs.aws.amazon.com/ses/latest/dg/regions.html") if {
	some name in resources_of_type("AWS::SES::ConfigurationSetEventDestination")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	arn := resolve(name, "Properties.EventDestination.KinesisFirehoseDestination.DeliveryStreamARN")
	_pf_ses_lit(arn)
	sr := _pf_ses_arn_region(arn)
	sr != region
}
