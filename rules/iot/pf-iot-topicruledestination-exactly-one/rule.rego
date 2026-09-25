package cdk_preflight

import rego.v1

_pf_iottrd_keys := ["HttpUrlProperties", "VpcProperties"]

violation contains make_diag_full("pf-iot-topicruledestination-exactly-one", "ERROR", name,
	"Properties",
	sprintf("%d of HttpUrlProperties / VpcProperties are set; CreateTopicRuleDestination answers \"Must provide exactly one of [HttpUrlConfiguration, VpcConfiguration, InfluxDBConfiguration]\"", [n]),
	"Keep exactly one of HttpUrlProperties and VpcProperties",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-topicruledestination.html") if {
	some name in resources_of_type("AWS::IoT::TopicRuleDestination")
	props := _pf_iotlib_props(name)
	n := count([k |
		some k in _pf_iottrd_keys
		object.get(props, k, "__pf_absent") != "__pf_absent"
	])
	n != 1
}
