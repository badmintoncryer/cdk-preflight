package cdk_preflight

import rego.v1

_pf_lemst_fix := "Drop StartingPositionTimestamp; it only applies to AT_TIMESTAMP on stream sources"

_pf_lemst_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"

violation contains make_diag_full("pf-lambda-esm-starting-position-timestamp-mq-unsupported", "ERROR", name,
	"Properties.StartingPositionTimestamp",
	"StartingPositionTimestamp on an Amazon MQ event source; broker queues have no offsets, so the mapping create is rejected",
	_pf_lemst_fix, _pf_lemst_url) if {
	some name in _pf_lam_esm
	_pf_lam_is(name, "mq")
	_pf_lam_has(name, "StartingPositionTimestamp")
}
