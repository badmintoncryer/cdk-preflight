package cdk_preflight

import rego.v1

_pf_elbgdd_fix := "Drop deregistration_delay.timeout_seconds on a lambda target group"

_pf_elbgdd_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

violation contains make_diag_full("pf-elbv2-tg-attr-dereg-delay-lambda", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Key", [p.index]),
	"deregistration_delay.timeout_seconds is set on a lambda target group; a Lambda target has no connections to drain",
	_pf_elbgdd_fix, _pf_elbgdd_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	p.key == "deregistration_delay.timeout_seconds"
	_pf_elb_tgtype(name) == "lambda"
}
