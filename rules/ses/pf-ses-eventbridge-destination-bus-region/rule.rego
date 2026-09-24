package cdk_preflight

import rego.v1

# SES は自分のリージョンのバスにしか publish できない。リージョン検査は
# cross-account 検査より先に走る（実測）ので、これが最初に出る文面になる。
violation contains make_diag_full("pf-ses-eventbridge-destination-bus-region", "ERROR", name,
	"Properties.EventDestination.EventBridgeDestination.EventBusArn",
	sprintf("the event bus is in '%v' but the event destination deploys to '%v'; the event destination create fails with \"Invalid Event Bridge destination, must be in region <%v>.\"", [br, region, region]),
	"Use the default event bus of the deployment Region",
	"https://docs.aws.amazon.com/ses/latest/dg/regions.html") if {
	some name in resources_of_type("AWS::SES::ConfigurationSetEventDestination")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	arn := resolve(name, "Properties.EventDestination.EventBridgeDestination.EventBusArn")
	_pf_ses_lit(arn)
	br := _pf_ses_arn_region(arn)
	br != region
}
