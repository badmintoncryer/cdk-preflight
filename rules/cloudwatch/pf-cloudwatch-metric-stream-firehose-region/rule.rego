package cdk_preflight

import rego.v1

# Needs the deploy environment (enforce mode only).
violation contains make_diag_full("pf-cloudwatch-metric-stream-firehose-region", "ERROR", name,
	"Properties.FirehoseArn",
	sprintf("FirehoseArn names region %s but the stack deploys to %s; PutMetricStream fails with \"FirehoseArn must be in the same region and AWS partition as the Metric Stream\"", [arn_region, region]),
	"Build the ARN with ${AWS::Region} (arn:${AWS::Partition}:firehose:${AWS::Region}:${AWS::AccountId}:deliverystream/<name>)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricStream.html") if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::CloudWatch::MetricStream")
	parts := _pf_cwlib_arn(resolve(name, "Properties.FirehoseArn"))
	parts[2] == "firehose"
	arn_region := parts[3]
	arn_region != region
}
