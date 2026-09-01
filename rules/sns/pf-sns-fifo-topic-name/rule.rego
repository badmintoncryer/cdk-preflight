package cdk_preflight

import rego.v1

_pf_snsfifo_fix := "Give FIFO topics a TopicName ending in '.fifo' (or drop TopicName to let CloudFormation generate one), and set FifoTopic: true whenever the name ends in '.fifo'"

_pf_snsfifo_url := "https://docs.aws.amazon.com/sns/latest/dg/sns-create-fifo-topic.html"

_pf_snsfifo_true(name) if resolve(name, "Properties.FifoTopic") in {true, "true"}

# FifoTopic が存在し、リテラル false 以外（true やトークン）なら「FIFO かもしれない」扱い
_pf_snsfifo_maybe_fifo(name) if {
	v := resolve(name, "Properties.FifoTopic")
	not v in {false, "false"}
}

violation contains make_diag_full("pf-sns-fifo-topic-name", "ERROR", name,
	"Properties.TopicName",
	sprintf("FifoTopic is true but TopicName '%s' does not end with '.fifo'; SNS rejects the topic at deploy time", [tn]),
	_pf_snsfifo_fix, _pf_snsfifo_url) if {
	some name in resources_of_type("AWS::SNS::Topic")
	_pf_snsfifo_true(name)
	tn := resolve(name, "Properties.TopicName")
	is_string(tn)
	not endswith(tn, ".fifo")
}

violation contains make_diag_full("pf-sns-fifo-topic-name", "ERROR", name,
	"Properties.TopicName",
	sprintf("TopicName '%s' ends with '.fifo' but FifoTopic is not true; SNS rejects the topic name at deploy time", [tn]),
	_pf_snsfifo_fix, _pf_snsfifo_url) if {
	some name in resources_of_type("AWS::SNS::Topic")
	tn := resolve(name, "Properties.TopicName")
	is_string(tn)
	endswith(tn, ".fifo")
	not _pf_snsfifo_maybe_fifo(name)
}
