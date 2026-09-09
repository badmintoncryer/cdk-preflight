package cdk_preflight

import rego.v1

_pf_elbglcd_fix := "Use a duration between 1 second and 7 days"

_pf_elbglcd_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

violation contains make_diag_full("pf-elbv2-tg-attr-lb-cookie-duration-range", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Value", [p.index]),
	sprintf("'%s' is %v, outside the accepted range 1-604800", [p.key, n]),
	_pf_elbglcd_fix, _pf_elbglcd_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	p.key == "stickiness.lb_cookie.duration_seconds"
	n := _pf_elb_num(p.value)
	_pf_elb_outside(n, 1, 604800)
}
