package cdk_preflight

import rego.v1

_pf_elbthct_fix := "Set HealthCheckProtocol to HTTP or HTTPS"

_pf_elbthct_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-hc-tcp-for-http-tg", "ERROR", name,
	"Properties.HealthCheckProtocol",
	sprintf("HealthCheckProtocol 'TCP' on a %s target group; the health check protocol of an HTTP/HTTPS target group must be HTTP or HTTPS", [p]),
	_pf_elbthct_fix, _pf_elbthct_url) if {
	some name in _pf_elb_tgs
	p := _pf_elb_str(name, "Protocol")
	p in _pf_elb_alb_protocols
	_pf_elb_str(name, "HealthCheckProtocol") == "TCP"
}
