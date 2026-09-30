package cdk_preflight

import rego.v1

_pf_mc_q_status_enum_url := "https://docs.aws.amazon.com/mediaconvert/latest/apireference/queues.html"

violation contains make_diag_full("pf-mediaconvert-q-status-enum", "ERROR", rn, "Properties.Status",
	sprintf("Queue Status is %s; it must be ACTIVE or PAUSED", [v]),
	"Use ACTIVE or PAUSED", _pf_mc_q_status_enum_url) if {
	some rn in resources_of_type("AWS::MediaConvert::Queue")
	p := input.resources[rn].properties
	is_object(p)
	v := p.Status
	is_string(v)
	not v in {"ACTIVE", "PAUSED"}
}
