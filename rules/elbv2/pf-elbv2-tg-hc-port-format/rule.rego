package cdk_preflight

import rego.v1

_pf_elbthcpt_fix := "Use traffic-port (with a hyphen) or a number between 1 and 65535"

_pf_elbthcpt_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-hc-port-format", "ERROR", name,
	"Properties.HealthCheckPort",
	sprintf("HealthCheckPort '%s' is neither traffic-port nor a port number in 1-65535", [v]),
	_pf_elbthcpt_fix, _pf_elbthcpt_url) if {
	some name in _pf_elb_tgs
	v := _pf_elb_str(name, "HealthCheckPort")
	v != "traffic-port"
	not _pf_elbthcpt_port(v)
}

_pf_elbthcpt_port(v) if {
	n := _pf_elb_num(v)
	n >= 1
	n <= 65535
}
