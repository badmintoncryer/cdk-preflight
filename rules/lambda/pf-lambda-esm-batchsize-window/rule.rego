package cdk_preflight

import rego.v1

# SQS-only coupling: big batches must wait for a window. Kinesis and
# DynamoDB sources take large batches without one, hence the SQS guard.
_pf_lbsw_is_sqs(name) if {
	resolve(name, "Properties.EventSourceArn") in resources_of_type("AWS::SQS::Queue")
}

_pf_lbsw_is_sqs(name) if {
	arn := resolve(name, "Properties.EventSourceArn")
	is_string(arn)
	startswith(arn, "arn:")
	split(arn, ":")[2] == "sqs"
}

_pf_lbsw_no_window(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "MaximumBatchingWindowInSeconds", "__pf_absent") == "__pf_absent"
}

_pf_lbsw_no_window(name) if {
	to_number(resolve(name, "Properties.MaximumBatchingWindowInSeconds")) == 0
}

violation contains make_diag_full("pf-lambda-esm-batchsize-window", "ERROR", name,
	"Properties.BatchSize",
	sprintf("BatchSize %v without a batching window; the mapping create fails with \"Invalid request provided: Maximum batch window in seconds must be greater than 0 if maximum batch size is greater than 10\"", [b]),
	"Set MaximumBatchingWindowInSeconds (1-300), or keep BatchSize at 10 or less",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html") if {
	some name in resources_of_type("AWS::Lambda::EventSourceMapping")
	_pf_lbsw_is_sqs(name)
	b := to_number(resolve(name, "Properties.BatchSize"))
	b > 10
	_pf_lbsw_no_window(name)
}
