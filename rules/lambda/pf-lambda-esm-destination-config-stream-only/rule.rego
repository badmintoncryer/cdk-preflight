package cdk_preflight

import rego.v1

_pf_ledcs_fix := "Drop DestinationConfig; SQS, Amazon MQ and DocumentDB sources have no on-failure destination"

_pf_ledcs_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"

violation contains make_diag_full("pf-lambda-esm-destination-config-stream-only", "ERROR", name,
	"Properties.DestinationConfig",
	"DestinationConfig on a source that does not support it; only stream sources report discarded batches to an on-failure destination",
	_pf_ledcs_fix, _pf_ledcs_url) if {
	some name in _pf_lam_esm
	_pf_lam_has(name, "DestinationConfig")
	some other in ["sqs","mq","docdb"]
	_pf_lam_is(name, other)
}
