package cdk_preflight

import rego.v1

# StartingPosition belongs to stream sources; queues have no offsets.
# Detected via an in-template queue sibling or the sqs arn segment.
_pf_lesp_is_sqs(name) if {
	resolve(name, "Properties.EventSourceArn") in resources_of_type("AWS::SQS::Queue")
}

_pf_lesp_is_sqs(name) if {
	arn := resolve(name, "Properties.EventSourceArn")
	is_string(arn)
	startswith(arn, "arn:")
	split(arn, ":")[2] == "sqs"
}

_pf_lesp_set(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "StartingPosition", "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-lambda-esm-sqs-starting-position", "ERROR", name,
	"Properties.StartingPosition",
	"StartingPosition on an SQS event source; the mapping create fails with \"Invalid request provided: StartingPosition is not valid for SQS event sources.\"",
	"Drop StartingPosition (it only applies to Kinesis/DynamoDB/Kafka sources)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html") if {
	some name in resources_of_type("AWS::Lambda::EventSourceMapping")
	_pf_lesp_is_sqs(name)
	_pf_lesp_set(name)
}
