package cdk_preflight

import rego.v1

# Needs the deploy environment (enforce mode only) - this is the layer that
# knows the target region.
violation contains make_diag_full("pf-cloudwatch-alarm-ec2-action-region", "ERROR", name,
	sprintf("Properties.%s", [key]),
	sprintf("The EC2 automate action names region %s but the stack deploys to %s; PutMetricAlarm fails with \"Invalid region %s specified. Only %s is supported.\"", [arn_region, region, arn_region, region]),
	"Build the action ARN with ${AWS::Region} (arn:${AWS::Partition}:automate:${AWS::Region}:ec2:stop)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html") if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	some key in _pf_cwlib_action_keys
	some item in flatten_list(name, sprintf("Properties.%s", [key]))
	parts := _pf_cwlib_arn(item.value)
	parts[2] == "automate"
	arn_region := parts[3]
	arn_region != region
}
