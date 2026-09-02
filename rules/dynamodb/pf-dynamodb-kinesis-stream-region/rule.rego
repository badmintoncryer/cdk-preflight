package cdk_preflight

import rego.v1

# A Kinesis Data Streams destination must live in the same region as the
# table. The deploy-time failure mode is ugly: the table is created, the
# streaming destination never stabilizes, and CloudFormation rolls back on
# NotStabilized minutes later — nothing names the region mismatch.
# data.cdk_preflight.deploy_region is defined only in enforce mode with a
# concrete region; otherwise this rule skips.
violation contains make_diag_full("pf-dynamodb-kinesis-stream-region", "ERROR", name,
	"Properties.KinesisStreamSpecification.StreamArn",
	sprintf("The Kinesis stream lives in '%s' but the table deploys to '%s'; the streaming destination never stabilizes and the stack rolls back", [streamRegion, region]),
	"Point KinesisStreamSpecification.StreamArn at a stream in the table's own region",
	"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/kds.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	arn := resolve(name, "Properties.KinesisStreamSpecification.StreamArn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "kinesis"
	streamRegion := parts[3]
	streamRegion != ""
	streamRegion != region
}
