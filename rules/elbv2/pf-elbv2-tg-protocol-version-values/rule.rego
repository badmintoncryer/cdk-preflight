package cdk_preflight

import rego.v1

_pf_elbtpvv_fix := "Use GRPC, HTTP1 or HTTP2"

_pf_elbtpvv_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-protocol-version-values", "ERROR", name,
	"Properties.ProtocolVersion",
	sprintf("ProtocolVersion '%s' is not one of GRPC, HTTP1, HTTP2", [pv]),
	_pf_elbtpvv_fix, _pf_elbtpvv_url) if {
	some name in _pf_elb_tgs
	pv := _pf_elb_str(name, "ProtocolVersion")
	not pv in {"GRPC", "HTTP1", "HTTP2"}
}
