package cdk_preflight

import rego.v1

_pf_elbtpvh_fix := "Drop ProtocolVersion, or set Protocol to HTTP or HTTPS"

_pf_elbtpvh_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-protocol-version-http-only", "ERROR", name,
	"Properties.ProtocolVersion",
	sprintf("ProtocolVersion is set on a %s target group; it only applies to HTTP and HTTPS target groups", [p]),
	_pf_elbtpvh_fix, _pf_elbtpvh_url) if {
	some name in _pf_elb_tgs
	p := _pf_elb_str(name, "Protocol")
	not p in _pf_elb_alb_protocols
	_pf_elb_has(name, "ProtocolVersion")
}
