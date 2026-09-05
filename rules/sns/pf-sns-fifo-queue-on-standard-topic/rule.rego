package cdk_preflight

import rego.v1

_pf_snsfqs_url := "https://docs.aws.amazon.com/sns/latest/dg/sns-fifo-topics.html"

_pf_snsfqs_fix := "Subscribe the FIFO queue to a FIFO topic, or use a standard queue"

_pf_snsfqs_sub contains [name, "Properties", sub, topic] if {
	some name in resources_of_type("AWS::SNS::Subscription")
	sub := input.resources[name].properties
	is_object(sub)
	topic := resolve(name, "Properties.TopicArn")
	is_string(topic)
}

_pf_snsfqs_sub contains [name, path, sub, name] if {
	some name in resources_of_type("AWS::SNS::Topic")
	some s in flatten_list(name, "Properties.Subscription")
	sub := s.value
	is_object(sub)
	path := sprintf("Properties.Subscription.%d", [s.index])
}

_pf_snsfqs_proto(name, path) := p if {
	p := resolve(name, sprintf("%s.Protocol", [path]))
	is_string(p)
}

# topic is FIFO: an in-template topic with FifoTopic true, or a literal ARN ending in .fifo
_pf_snsfqs_tfifo(t) if {
	t in resources_of_type("AWS::SNS::Topic")
	resolve(t, "Properties.FifoTopic") in {true, "true"}
}

_pf_snsfqs_tfifo(t) if {
	startswith(t, "arn:")
	endswith(t, ".fifo")
}

_pf_snsfqs_tstd(t) if {
	t in resources_of_type("AWS::SNS::Topic")
	props := input.resources[t].properties
	is_object(props)
	object.get(props, "FifoTopic", "__pf_absent") == "__pf_absent"
}

_pf_snsfqs_tstd(t) if {
	t in resources_of_type("AWS::SNS::Topic")
	resolve(t, "Properties.FifoTopic") in {false, "false"}
}

_pf_snsfqs_tstd(t) if {
	startswith(t, "arn:")
	not endswith(t, ".fifo")
}

_pf_snsfqs_qfifo(ep) if {
	ep in resources_of_type("AWS::SQS::Queue")
	resolve(ep, "Properties.FifoQueue") in {true, "true"}
}

_pf_snsfqs_qfifo(ep) if {
	startswith(ep, "arn:")
	endswith(ep, ".fifo")
}

violation contains make_diag_full("pf-sns-fifo-queue-on-standard-topic", "ERROR", name,
	sprintf("%s.Endpoint", [path]),
	"a FIFO queue is subscribed to a standard topic; Subscribe fails with \"Invalid parameter: Endpoint Reason: FIFO SQS Queues can not be subscribed to standard SNS topics\"",
	_pf_snsfqs_fix, _pf_snsfqs_url) if {
	some [name, path, sub, topic] in _pf_snsfqs_sub
	_pf_snsfqs_tstd(topic)
	_pf_snsfqs_proto(name, path) == "sqs"
	ep := resolve(name, sprintf("%s.Endpoint", [path]))
	is_string(ep)
	_pf_snsfqs_qfifo(ep)
}
