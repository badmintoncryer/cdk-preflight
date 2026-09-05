package cdk_preflight

import rego.v1

_pf_snsraw_url := "https://docs.aws.amazon.com/sns/latest/api/API_Subscribe.html"

_pf_snsraw_fix := "Drop RawMessageDelivery for email / email-json / sms / lambda / application subscriptions"

_pf_snsraw_sub contains [name, "Properties", sub, topic] if {
	some name in resources_of_type("AWS::SNS::Subscription")
	sub := input.resources[name].properties
	is_object(sub)
	topic := resolve(name, "Properties.TopicArn")
	is_string(topic)
}

_pf_snsraw_sub contains [name, path, sub, name] if {
	some name in resources_of_type("AWS::SNS::Topic")
	some s in flatten_list(name, "Properties.Subscription")
	sub := s.value
	is_object(sub)
	path := sprintf("Properties.Subscription.%d", [s.index])
}

_pf_snsraw_proto(name, path) := p if {
	p := resolve(name, sprintf("%s.Protocol", [path]))
	is_string(p)
}

violation contains make_diag_full("pf-sns-raw-message-delivery", "ERROR", name,
	sprintf("%s.RawMessageDelivery", [path]),
	sprintf("RawMessageDelivery is true on a %s subscription; Subscribe fails with \"Invalid parameter: Attributes Reason: Delivery protocol [%s] does not support raw message delivery.\"", [proto, proto]),
	_pf_snsraw_fix, _pf_snsraw_url) if {
	some [name, path, sub, _] in _pf_snsraw_sub
	resolve(name, sprintf("%s.RawMessageDelivery", [path])) in {true, "true"}
	proto := _pf_snsraw_proto(name, path)
	not proto in {"sqs", "http", "https", "firehose"}
}
