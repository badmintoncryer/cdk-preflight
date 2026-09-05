package cdk_preflight

import rego.v1

_pf_sqsrr_url := "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html"

_pf_sqsrr_fix := "Reference queues in the same region (Fn::GetAtt Queue.Arn of queues in this stack)"

# RedrivePolicy arrives as a JSON object or as a JSON string (both are valid CloudFormation).
_pf_sqsrr_pol(name) := pol if {
	pol := object.get(input.resources[name].properties, "RedrivePolicy", null)
	is_object(pol)
}

_pf_sqsrr_pol(name) := pol if {
	raw := object.get(input.resources[name].properties, "RedrivePolicy", null)
	is_string(raw)
	pol := json.unmarshal(raw)
	is_object(pol)
}

_pf_sqsrr_allow(name) := pol if {
	pol := object.get(input.resources[name].properties, "RedriveAllowPolicy", null)
	is_object(pol)
}

_pf_sqsrr_allow(name) := pol if {
	raw := object.get(input.resources[name].properties, "RedriveAllowPolicy", null)
	is_string(raw)
	pol := json.unmarshal(raw)
	is_object(pol)
}

_pf_sqsrr_region(arn) := parts[3] if {
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) >= 6
	parts[2] == "sqs"
}

# Region comparison needs the deploy region, which only this pack sees
# (data.cdk_preflight.deploy_region is defined in enforce mode; the rule
# skips without it).
violation contains make_diag_full("pf-sqs-redrive-arn-region", "ERROR", name,
	"Properties.RedrivePolicy.deadLetterTargetArn",
	sprintf("deadLetterTargetArn is in '%s' but the queue deploys to '%s'; CreateQueue fails with \"Dead-letter target must be in same region as the source.\"", [r, region]),
	_pf_sqsrr_fix, _pf_sqsrr_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::SQS::Queue")
	arn := object.get(_pf_sqsrr_pol(name), "deadLetterTargetArn", null)
	is_string(arn)
	r := _pf_sqsrr_region(arn)
	r != region
}

violation contains make_diag_full("pf-sqs-redrive-arn-region", "ERROR", name,
	sprintf("Properties.RedriveAllowPolicy.sourceQueueArns.%d", [i]),
	sprintf("source queue '%s' is in '%s' but the queue deploys to '%s'; CreateQueue fails with \"All source queue ARNs must be in the same region as the current SQS queue.\"", [arn, r, region]),
	_pf_sqsrr_fix, _pf_sqsrr_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::SQS::Queue")
	arns := object.get(_pf_sqsrr_allow(name), "sourceQueueArns", null)
	is_array(arns)
	some i, arn in arns
	is_string(arn)
	r := _pf_sqsrr_region(arn)
	r != region
}
