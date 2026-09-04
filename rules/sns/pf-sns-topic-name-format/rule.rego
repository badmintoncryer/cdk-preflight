package cdk_preflight

import rego.v1

_pf_snsname_ok(n) if regex.match(`^[a-zA-Z0-9_-]{1,256}$`, n)

_pf_snsname_ok(n) if regex.match(`^[a-zA-Z0-9_-]{1,251}\.fifo$`, n)

violation contains make_diag_full("pf-sns-topic-name-format", "ERROR", name,
	"Properties.TopicName",
	sprintf("TopicName '%s' is rejected with \"Invalid parameter: Topic Name\": SNS accepts only letters, numbers, hyphen and underscore (a FIFO topic adds the .fifo suffix)", [n]),
	"Rename the topic using [a-zA-Z0-9_-] (append .fifo only for FIFO topics)",
	"https://docs.aws.amazon.com/sns/latest/api/API_CreateTopic.html") if {
	some name in resources_of_type("AWS::SNS::Topic")
	n := resolve(name, "Properties.TopicName")
	is_string(n)
	not _pf_snsname_ok(n)
}
