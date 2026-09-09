package cdk_preflight

import rego.v1

_pf_elbthce_fix := "Leave HealthCheckEnabled at true (only a lambda target group may disable it)"

_pf_elbthce_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-hc-enabled-required", "ERROR", name,
	"Properties.HealthCheckEnabled",
	sprintf("HealthCheckEnabled is false on a '%s' target group; health checks are required unless the target type is lambda", [t]),
	_pf_elbthce_fix, _pf_elbthce_url) if {
	some name in _pf_elb_tgs
	t := _pf_elb_tgtype(name)
	t != "lambda"
	resolve(name, "Properties.HealthCheckEnabled") == false
}
