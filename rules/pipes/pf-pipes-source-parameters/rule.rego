package cdk_preflight

import rego.v1

# CreatePipe checks the SourceParameters block against the source ARN's
# service ("Invalid source parameter provided for source") and demands the
# matching block for stream sources ("SourceParameters.KinesisStreamParameters
# Missing required parameter."). Measured 2026-09-07, pipes:CreatePipe,
# us-east-1. SelfManagedKafkaParameters is excluded: its source is an
# smk:// URI rather than an ARN.
_pf_pipesrc_block_service := {
	"KinesisStreamParameters": "kinesis",
	"DynamoDBStreamParameters": "dynamodb",
	"SqsQueueParameters": "sqs",
	"ManagedStreamingKafkaParameters": "kafka",
	"ActiveMQBrokerParameters": "mq",
	"RabbitMQBrokerParameters": "mq",
}

# Stream sources carry a mandatory StartingPosition, so the block itself is
# required. Measured for both kinesis and dynamodb.
_pf_pipesrc_required := {"kinesis": "KinesisStreamParameters", "dynamodb": "DynamoDBStreamParameters"}

_pf_pipesrc_service(name) := parts[2] if {
	arn := resolve(name, "Properties.Source")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) > 2
}

violation contains make_diag_full("pf-pipes-source-parameters", "ERROR", name,
	sprintf("Properties.SourceParameters.%s", [block]),
	sprintf("%s only applies to a %s source but the pipe reads from %s; CreatePipe fails with \"Invalid source parameter provided for source\"", [block, want, svc]),
	sprintf("Remove %s, or point Source at a %s resource", [block, want]),
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-pipes-pipe-pipesourceparameters.html") if {
	some name in resources_of_type("AWS::Pipes::Pipe")
	sp := input.resources[name].properties.SourceParameters
	is_object(sp)
	some block, want in _pf_pipesrc_block_service
	object.get(sp, block, "__pf_absent") != "__pf_absent"
	svc := _pf_pipesrc_service(name)
	svc != want
}

violation contains make_diag_full("pf-pipes-source-parameters", "ERROR", name,
	sprintf("Properties.SourceParameters.%s", [block]),
	sprintf("A %s stream source needs %s (StartingPosition is mandatory); CreatePipe fails with \"SourceParameters.%s Missing required parameter.\"", [svc, block, block]),
	sprintf("Add SourceParameters.%s with a StartingPosition", [block]),
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-pipes-pipe-pipesourceparameters.html") if {
	some name in resources_of_type("AWS::Pipes::Pipe")
	svc := _pf_pipesrc_service(name)
	block := _pf_pipesrc_required[svc]
	sp := object.get(input.resources[name].properties, "SourceParameters", {})
	object.get(sp, block, "__pf_absent") == "__pf_absent"
}
