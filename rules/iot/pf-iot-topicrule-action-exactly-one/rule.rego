package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-topicrule-action-exactly-one", "ERROR", name,
	sprintf("Properties.TopicRulePayload.Actions.%d", [i]),
	sprintf("this Actions entry defines %d actions; CreateTopicRule answers \"Each object in the actions list can only have one action defined\" (and \"Empty actions are not allowed. Please define one type of action\" when the entry is empty)", [count(a)]),
	"Split the entry so that every element of Actions carries exactly one action",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_Action.html") if {
	some [name, i, a] in _pf_iotlib_action
	count(a) != 1
}
