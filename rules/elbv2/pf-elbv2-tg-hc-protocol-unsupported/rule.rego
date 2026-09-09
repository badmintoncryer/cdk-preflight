package cdk_preflight

import rego.v1

_pf_elbthcp_fix := "Set HealthCheckProtocol to HTTP, HTTPS or TCP"

_pf_elbthcp_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-hc-protocol-unsupported", "ERROR", name,
	"Properties.HealthCheckProtocol",
	sprintf("HealthCheckProtocol '%s' is not a health check protocol; the service only probes over HTTP, HTTPS or TCP", [hp]),
	_pf_elbthcp_fix, _pf_elbthcp_url) if {
	some name in _pf_elb_tgs
	hp := _pf_elb_str(name, "HealthCheckProtocol")
	not hp in _pf_elb_hc_protocols
}
