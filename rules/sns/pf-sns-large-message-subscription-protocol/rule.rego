package cdk_preflight

import rego.v1

# [resource holding the subscription, its path, topic logical id]
_pf_snslmp_sub contains [name, "Properties", topic] if {
	some name in resources_of_type("AWS::SNS::Subscription")
	topic := resolve(name, "Properties.TopicArn")
	is_string(topic)
	topic in resources_of_type("AWS::SNS::Topic")
}

_pf_snslmp_sub contains [name, path, name] if {
	some name in resources_of_type("AWS::SNS::Topic")
	some s in flatten_list(name, "Properties.Subscription")
	is_object(s.value)
	path := sprintf("Properties.Subscription.%d", [s.index])
}

_pf_snslmp_size(t) := n if {
	v := resolve(t, "Properties.MaximumMessageSize")
	not is_boolean(v)
	v != null
	n := to_number(v)
}

violation contains make_diag_full("pf-sns-large-message-subscription-protocol", "ERROR", name,
	sprintf("%s.Protocol", [path]),
	sprintf("topic %s has MaximumMessageSize %v but this subscription uses protocol %s; SNS fails with \"Invalid parameter: MaximumMessageSize greater than 262144 bytes is not supported for the following protocol: [%s]\"", [topic, n, p, p]),
	"Keep MaximumMessageSize at or below 262144, or subscribe only sqs / lambda / firehose endpoints",
	"https://docs.aws.amazon.com/sns/latest/dg/large-message-payloads.html") if {
	some [name, path, topic] in _pf_snslmp_sub
	n := _pf_snslmp_size(topic)
	n > 262144
	p := resolve(name, sprintf("%s.Protocol", [path]))
	is_string(p)
	not input.resources[p]
	not lower(p) in {"sqs", "lambda", "firehose"}
}
