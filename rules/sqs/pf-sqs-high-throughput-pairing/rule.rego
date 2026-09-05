package cdk_preflight

import rego.v1

_pf_sqsht_url := "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/high-throughput-fifo.html"

_pf_sqsht_fix := "Set DeduplicationScope: messageGroup together with FifoThroughputLimit: perMessageGroupId (both are needed for high throughput)"

violation contains make_diag_full("pf-sqs-high-throughput-pairing", "ERROR", name,
	"Properties.FifoThroughputLimit",
	sprintf("FifoThroughputLimit is perMessageGroupId but DeduplicationScope is %s; CreateQueue fails with \"Invalid value for the parameter FifoThroughputLimit. Reason: To set FifoThroughputLimit to perMessageGroupId, the DeduplicationScope must be messageGroup.\"", [shown]),
	_pf_sqsht_fix, _pf_sqsht_url) if {
	some name in resources_of_type("AWS::SQS::Queue")
	resolve(name, "Properties.FifoThroughputLimit") == "perMessageGroupId"
	props := input.resources[name].properties
	is_object(props)
	scope := object.get(props, "DeduplicationScope", null)
	_pf_sqsht_bad(scope)
	shown := _pf_sqsht_show(scope)
}

_pf_sqsht_bad(scope) if scope == null

_pf_sqsht_bad(scope) if {
	is_string(scope)
	scope != "messageGroup"
}

_pf_sqsht_show(scope) := "absent" if scope == null

_pf_sqsht_show(scope) := sprintf("'%s'", [scope]) if is_string(scope)
