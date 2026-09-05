package cdk_preflight

import rego.v1

_pf_snsep_url := "https://docs.aws.amazon.com/sns/latest/api/API_Subscribe.html"

_pf_snsep_fix := "Give the subscription the endpoint form its protocol expects (Fn::GetAtt Queue.Arn for sqs, https:// URL for https, ...)"

_pf_snsep_sub contains [name, "Properties", sub, topic] if {
	some name in resources_of_type("AWS::SNS::Subscription")
	sub := input.resources[name].properties
	is_object(sub)
	topic := resolve(name, "Properties.TopicArn")
	is_string(topic)
}

_pf_snsep_sub contains [name, path, sub, name] if {
	some name in resources_of_type("AWS::SNS::Topic")
	some s in flatten_list(name, "Properties.Subscription")
	sub := s.value
	is_object(sub)
	path := sprintf("Properties.Subscription.%d", [s.index])
}

_pf_snsep_proto(name, path) := p if {
	p := resolve(name, sprintf("%s.Protocol", [path]))
	is_string(p)
}

_pf_snsep_protocols := {"http", "https", "email", "email-json", "sms", "sqs", "application", "lambda", "firehose"}

violation contains make_diag_full("pf-sns-subscription-endpoint", "ERROR", name,
	sprintf("%s.Protocol", [path]),
	sprintf("Protocol '%s' is not an SNS protocol; Subscribe fails with \"Invalid parameter: Amazon SNS does not support this protocol string: %s\"", [proto, proto]),
	_pf_snsep_fix, _pf_snsep_url) if {
	some [name, path, sub, _] in _pf_snsep_sub
	proto := _pf_snsep_proto(name, path)
	not proto in _pf_snsep_protocols
}

# [protocol, endpoint pattern, service error]
_pf_snsep_shape contains ["sqs", "^arn:[^:]+:sqs:", "Invalid parameter: SQS endpoint ARN"]

_pf_snsep_shape contains ["lambda", "^arn:[^:]+:lambda:", "Invalid parameter: Lambda endpoint ARN"]

_pf_snsep_shape contains ["firehose", "^arn:[^:]+:firehose:", "Invalid parameter: Firehose endpoint ARN"]

_pf_snsep_shape contains ["application", "^arn:[^:]+:sns:[^:]*:[^:]*:endpoint/", "Invalid parameter: Application endpoint arn invalid"]

_pf_snsep_shape contains ["email", "^[^@ ]+@[^@ ]+$", "Invalid parameter: Email address"]

_pf_snsep_shape contains ["email-json", "^[^@ ]+@[^@ ]+$", "Invalid parameter: Email address"]

_pf_snsep_shape contains ["http", "^http://", "Invalid parameter: Endpoint must match the specified protocol"]

_pf_snsep_shape contains ["https", "^https://", "Invalid parameter: Endpoint must match the specified protocol"]

_pf_snsep_shape contains ["sms", "^[+]?[0-9][0-9 -]*$", "Invalid SMS endpoint"]

# Only literal endpoints are judged: a Ref / Fn::GetAtt to a resource in the
# template resolves to that resource's logical ID and is skipped.
violation contains make_diag_full("pf-sns-subscription-endpoint", "ERROR", name,
	sprintf("%s.Endpoint", [path]),
	sprintf("Endpoint '%s' does not have the form the %s protocol expects; Subscribe fails with \"%s\"", [ep, proto, err]),
	_pf_snsep_fix, _pf_snsep_url) if {
	some [name, path, sub, _] in _pf_snsep_sub
	proto := _pf_snsep_proto(name, path)
	some [p2, pattern, err] in _pf_snsep_shape
	p2 == proto
	ep := resolve(name, sprintf("%s.Endpoint", [path]))
	is_string(ep)
	not ep in object.keys(input.resources)
	not contains(ep, "${")
	not regex.match(pattern, ep)
}
