package cdk_preflight

import rego.v1

_pf_sqssse_url := "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_CreateQueue.html"

_pf_sqssse_fix := "Keep either SqsManagedSseEnabled: true (SSE-SQS) or KmsMasterKeyId (SSE-KMS); SqsManagedSseEnabled: false with a key is fine"

violation contains make_diag_full("pf-sqs-sse-exclusive", "ERROR", name,
	"Properties.KmsMasterKeyId",
	"SqsManagedSseEnabled is true and KmsMasterKeyId is set; CreateQueue fails with \"You can use one type of server-side encryption (SSE) at one time. You can either enable KMS SSE or SQS SSE.\"",
	_pf_sqssse_fix, _pf_sqssse_url) if {
	some name in resources_of_type("AWS::SQS::Queue")
	resolve(name, "Properties.SqsManagedSseEnabled") in {true, "true"}
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "KmsMasterKeyId", "__pf_absent") != "__pf_absent"
}
