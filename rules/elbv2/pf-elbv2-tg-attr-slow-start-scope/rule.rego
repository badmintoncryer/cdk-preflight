package cdk_preflight

import rego.v1

_pf_elbgss_fix := "Drop slow_start.duration_seconds unless the target group is HTTP/HTTPS with instance or ip targets"

_pf_elbgss_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

violation contains make_diag_full("pf-elbv2-tg-attr-slow-start-scope", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Key", [p.index]),
	sprintf("slow_start.duration_seconds is set on a %s target group with target type '%s'; slow start only applies to an Application Load Balancer target group of instance or ip targets", [f, t]),
	_pf_elbgss_fix, _pf_elbgss_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	p.key == "slow_start.duration_seconds"
	f := object.get(_pf_elb_family_of, object.get(_pf_elb_props(name), "Protocol", ""), "lambda")
	t := _pf_elb_tgtype(name)
	not _pf_elbgss_ok(f, t)
}

_pf_elbgss_ok(f, t) if {
	f == "application"
	t in {"instance", "ip"}
}
