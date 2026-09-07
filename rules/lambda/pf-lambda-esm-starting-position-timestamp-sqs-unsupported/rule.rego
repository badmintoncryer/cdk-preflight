package cdk_preflight

import rego.v1

_pf_lestt_fix := "Drop StartingPositionTimestamp; it only applies to AT_TIMESTAMP on stream sources"

_pf_lestt_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"

violation contains make_diag_full("pf-lambda-esm-starting-position-timestamp-sqs-unsupported", "ERROR", name,
	"Properties.StartingPositionTimestamp",
	"StartingPositionTimestamp on an SQS event source; queues have no offsets, so the mapping create is rejected",
	_pf_lestt_fix, _pf_lestt_url) if {
	some name in _pf_lam_esm
	_pf_lam_is(name, "sqs")
	_pf_lam_has(name, "StartingPositionTimestamp")
}
