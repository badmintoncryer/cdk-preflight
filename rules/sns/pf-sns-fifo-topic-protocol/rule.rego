package cdk_preflight

import rego.v1

_pf_snsftp_url := "https://docs.aws.amazon.com/sns/latest/dg/sns-fifo-topics.html"

_pf_snsftp_fix := "Subscribe an SQS queue (FIFO or standard) to the FIFO topic, or use a standard topic for other protocols"

_pf_snsftp_sub contains [name, "Properties", sub, topic] if {
	some name in resources_of_type("AWS::SNS::Subscription")
	sub := input.resources[name].properties
	is_object(sub)
	topic := resolve(name, "Properties.TopicArn")
	is_string(topic)
}

_pf_snsftp_sub contains [name, path, sub, name] if {
	some name in resources_of_type("AWS::SNS::Topic")
	some s in flatten_list(name, "Properties.Subscription")
	sub := s.value
	is_object(sub)
	path := sprintf("Properties.Subscription.%d", [s.index])
}

_pf_snsftp_proto(name, path) := p if {
	p := resolve(name, sprintf("%s.Protocol", [path]))
	is_string(p)
}

# topic is FIFO: an in-template topic with FifoTopic true, or a literal ARN ending in .fifo
_pf_snsftp_tfifo(t) if {
	t in resources_of_type("AWS::SNS::Topic")
	resolve(t, "Properties.FifoTopic") in {true, "true"}
}

_pf_snsftp_tfifo(t) if {
	startswith(t, "arn:")
	endswith(t, ".fifo")
}

_pf_snsftp_tstd(t) if {
	t in resources_of_type("AWS::SNS::Topic")
	props := input.resources[t].properties
	is_object(props)
	object.get(props, "FifoTopic", "__pf_absent") == "__pf_absent"
}

_pf_snsftp_tstd(t) if {
	t in resources_of_type("AWS::SNS::Topic")
	resolve(t, "Properties.FifoTopic") in {false, "false"}
}

_pf_snsftp_tstd(t) if {
	startswith(t, "arn:")
	not endswith(t, ".fifo")
}

violation contains make_diag_full("pf-sns-fifo-topic-protocol", "ERROR", name,
	sprintf("%s.Protocol", [path]),
	sprintf("a FIFO topic is subscribed with protocol %s; Subscribe fails with \"Invalid parameter: Invalid protocol type: %s\"", [proto, proto]),
	_pf_snsftp_fix, _pf_snsftp_url) if {
	some [name, path, sub, topic] in _pf_snsftp_sub
	_pf_snsftp_tfifo(topic)
	proto := _pf_snsftp_proto(name, path)
	proto != "sqs"
}
