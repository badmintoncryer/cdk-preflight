package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-sql-from-topic-filter", "ERROR", name,
	"Properties.TopicRulePayload.Sql",
	sprintf("the FROM topic filter '%s' is not a valid MQTT topic filter: '#' must be the last level and alone in it, and '+' must be alone in its level; CreateTopicRule answers \"The MQTT topic you provided is invalid.\"", [tf]),
	"Write the wildcard as its own level, with '#' last (for example 'a/+/b' or 'a/b/#')",
	"https://docs.aws.amazon.com/iot/latest/developerguide/topics.html") if {
	some name in resources_of_type("AWS::IoT::TopicRule")
	tf := _pf_iotlib_topic(_pf_iotlib_sql(name))
	_pf_iotlib_topic_bad(tf)
}
