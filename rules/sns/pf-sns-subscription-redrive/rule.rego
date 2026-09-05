package cdk_preflight

import rego.v1

_pf_snssrd_url := "https://docs.aws.amazon.com/sns/latest/dg/sns-dead-letter-queues.html"

_pf_snssrd_fix := "Set deadLetterTargetArn to Fn::GetAtt Queue.Arn of a queue in this stack"

_pf_snssrd_sub contains [name, "Properties", sub, topic] if {
	some name in resources_of_type("AWS::SNS::Subscription")
	sub := input.resources[name].properties
	is_object(sub)
	topic := resolve(name, "Properties.TopicArn")
	is_string(topic)
}

_pf_snssrd_sub contains [name, path, sub, name] if {
	some name in resources_of_type("AWS::SNS::Topic")
	some s in flatten_list(name, "Properties.Subscription")
	sub := s.value
	is_object(sub)
	path := sprintf("Properties.Subscription.%d", [s.index])
}

_pf_snssrd_proto(name, path) := p if {
	p := resolve(name, sprintf("%s.Protocol", [path]))
	is_string(p)
}

_pf_snssrd_pol(sub) := pol if {
	pol := object.get(sub, "RedrivePolicy", null)
	is_object(pol)
}

_pf_snssrd_pol(sub) := pol if {
	raw := object.get(sub, "RedrivePolicy", null)
	is_string(raw)
	pol := json.unmarshal(raw)
	is_object(pol)
}

violation contains make_diag_full("pf-sns-subscription-redrive", "ERROR", name,
	sprintf("%s.RedrivePolicy", [path]),
	"RedrivePolicy has no deadLetterTargetArn; Subscribe fails with \"Invalid parameter: Attributes Reason: RedrivePolicy: Missing deadLetterTargetArn attribute\"",
	_pf_snssrd_fix, _pf_snssrd_url) if {
	some [name, path, sub, _] in _pf_snssrd_sub
	pol := _pf_snssrd_pol(sub)
	object.get(pol, "deadLetterTargetArn", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-sns-subscription-redrive", "ERROR", name,
	sprintf("%s.RedrivePolicy.deadLetterTargetArn", [path]),
	sprintf("deadLetterTargetArn '%s' is not an SQS queue ARN; Subscribe fails with \"Invalid parameter: Attributes Reason: RedrivePolicy: deadLetterTargetArn must be a SQS queue\"", [arn]),
	_pf_snssrd_fix, _pf_snssrd_url) if {
	some [name, path, sub, _] in _pf_snssrd_sub
	arn := object.get(_pf_snssrd_pol(sub), "deadLetterTargetArn", null)
	is_string(arn)
	not contains(arn, "${")
	not regex.match("^arn:[^:]+:sqs:", arn)
}

# Region comparison needs the deploy region (enforce mode only; see AGENTS.md).
violation contains make_diag_full("pf-sns-subscription-redrive", "ERROR", name,
	sprintf("%s.RedrivePolicy.deadLetterTargetArn", [path]),
	sprintf("deadLetterTargetArn is in '%s' but the subscription deploys to '%s'; Subscribe fails with \"Invalid parameter: Attributes Reason: RedrivePolicy: deadLetterTargetArn must be in the same region as the subscription\"", [parts[3], region]),
	_pf_snssrd_fix, _pf_snssrd_url) if {
	region := data.cdk_preflight.deploy_region
	some [name, path, sub, _] in _pf_snssrd_sub
	arn := object.get(_pf_snssrd_pol(sub), "deadLetterTargetArn", null)
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[2] == "sqs"
	parts[3] != region
}
