package cdk_preflight

import rego.v1

_pf_elbtpr_fix := "Set Protocol and Port (they are only omitted for a lambda target group)"

_pf_elbtpr_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-protocol-required-non-lambda", "ERROR", name,
	sprintf("Properties.%s", [k]),
	sprintf("TargetType is '%s' but %s is missing; CreateTargetGroup fails with \"A target group of type '%s' must have a protocol and a port\"", [t, k, t]),
	_pf_elbtpr_fix, _pf_elbtpr_url) if {
	some name in _pf_elb_tgs
	t := _pf_elb_tgtype(name)
	t != "lambda"
	some k in ["Protocol", "Port"]
	_pf_elb_absent(name, k)
}
