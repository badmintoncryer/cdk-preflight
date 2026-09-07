package cdk_preflight

import rego.v1

_pf_lemsp_fix := "Drop StartingPosition; it only applies to stream sources"

_pf_lemsp_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"

violation contains make_diag_full("pf-lambda-esm-mq-starting-position-unsupported", "ERROR", name,
	"Properties.StartingPosition",
	"StartingPosition on an Amazon MQ event source; broker queues have no offsets, so the mapping create is rejected",
	_pf_lemsp_fix, _pf_lemsp_url) if {
	some name in _pf_lam_esm
	_pf_lam_is(name, "mq")
	_pf_lam_has(name, "StartingPosition")
}
