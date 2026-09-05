package cdk_preflight

import rego.v1

_pf_sqsrp_url := "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html"

_pf_sqsrp_fix := "Set both deadLetterTargetArn (Fn::GetAtt Queue.Arn) and maxReceiveCount between 1 and 1000"

# RedrivePolicy arrives as a JSON object or as a JSON string (both are valid CloudFormation).
_pf_sqsrp_pol(name) := pol if {
	pol := object.get(input.resources[name].properties, "RedrivePolicy", null)
	is_object(pol)
}

_pf_sqsrp_pol(name) := pol if {
	raw := object.get(input.resources[name].properties, "RedrivePolicy", null)
	is_string(raw)
	pol := json.unmarshal(raw)
	is_object(pol)
}

violation contains make_diag_full("pf-sqs-redrive-policy", "ERROR", name,
	sprintf("Properties.RedrivePolicy.%s", [key]),
	sprintf("RedrivePolicy has no %s; CreateQueue fails with \"Redrive policy does not contain mandatory attribute: %s.\"", [key, key]),
	_pf_sqsrp_fix, _pf_sqsrp_url) if {
	some name in resources_of_type("AWS::SQS::Queue")
	pol := _pf_sqsrp_pol(name)
	some key in ["deadLetterTargetArn", "maxReceiveCount"]
	object.get(pol, key, "__pf_absent") == "__pf_absent"
}

_pf_sqsrp_num(v) := v if is_number(v)

_pf_sqsrp_num(v) := to_number(v) if {
	is_string(v)
	regex.match("^[0-9]+$", v)
}

violation contains make_diag_full("pf-sqs-redrive-policy", "ERROR", name,
	"Properties.RedrivePolicy.maxReceiveCount",
	sprintf("maxReceiveCount %v is outside 1..1000; CreateQueue fails with \"Invalid value for maxReceiveCount: %v, valid values are from 1 to 1000 both inclusive.\"", [n, n]),
	_pf_sqsrp_fix, _pf_sqsrp_url) if {
	some name in resources_of_type("AWS::SQS::Queue")
	pol := _pf_sqsrp_pol(name)
	n := _pf_sqsrp_num(object.get(pol, "maxReceiveCount", null))
	_pf_sqsrp_out(n)
}

_pf_sqsrp_out(n) if n < 1

_pf_sqsrp_out(n) if n > 1000

violation contains make_diag_full("pf-sqs-redrive-policy", "ERROR", name,
	"Properties.RedrivePolicy.deadLetterTargetArn",
	sprintf("deadLetterTargetArn '%s' is not an SQS queue ARN; CreateQueue fails with \"Only SQS queues are valid resources for deadLetterTargetArn\"", [arn]),
	_pf_sqsrp_fix, _pf_sqsrp_url) if {
	some name in resources_of_type("AWS::SQS::Queue")
	pol := _pf_sqsrp_pol(name)
	arn := object.get(pol, "deadLetterTargetArn", null)
	is_string(arn)
	not contains(arn, "${")
	not regex.match("^arn:[^:]+:sqs:", arn)
}
