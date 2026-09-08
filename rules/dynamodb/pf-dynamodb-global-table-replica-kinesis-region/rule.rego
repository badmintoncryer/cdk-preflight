package cdk_preflight

import rego.v1

# The GlobalTable counterpart of pf-dynamodb-kinesis-stream-region. The
# failure mode is the same: the replica never stabilizes and the stack rolls
# back without naming the Region mismatch.
violation contains make_diag_full("pf-dynamodb-global-table-replica-kinesis-region", "ERROR", name,
	sprintf("Properties.Replicas.%d.KinesisStreamSpecification.StreamArn", [r.index]),
	sprintf("Replica '%s' streams to a Kinesis stream in '%s'; the destination must be in the replica's own Region", [region, streamRegion]),
	"Create one Kinesis stream per replica Region and point each replica at its own",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-globaltable-kinesisstreamspecification.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	some r in flatten_list(name, "Properties.Replicas")
	region := object.get(r.value, "Region", null)
	is_string(region)
	ks := object.get(r.value, "KinesisStreamSpecification", null)
	is_object(ks)
	arn := object.get(ks, "StreamArn", null)
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "kinesis"
	streamRegion := parts[3]
	streamRegion != ""
	streamRegion != region
}
