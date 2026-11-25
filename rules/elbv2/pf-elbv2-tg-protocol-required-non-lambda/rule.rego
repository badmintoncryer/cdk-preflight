package cdk_preflight

import rego.v1

_pf_elbtpr_fix := "Set Protocol and Port (they are only omitted for a lambda target group)"

_pf_elbtpr_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-protocol-required-non-lambda", "ERROR", name,
	sprintf("Properties.%s", [k]),
	sprintf("TargetType is '%s' but %s is missing; CreateTargetGroup fails with \"%s\"", [t, k, _pf_elbtpr_error(name, k, t)]),
	_pf_elbtpr_fix, _pf_elbtpr_url) if {
	some name in _pf_elb_tgs
	t := _pf_elb_tgtype(name)
	t != "lambda"
	some k in ["Protocol", "Port"]
	_pf_elb_absent(name, k)
}

# Measured messages (bench 2026-11-25): both missing -> "A target group of type
# '<t>' must have a protocol and a port"; one missing -> "A port must be
# specified" / "A protocol must be specified".
_pf_elbtpr_error(name, _, t) := sprintf("A target group of type '%s' must have a protocol and a port", [t]) if {
	_pf_elb_absent(name, "Protocol")
	_pf_elb_absent(name, "Port")
}

_pf_elbtpr_error(name, k, _) := sprintf("A %s must be specified", [lower(k)]) if {
	not _pf_elbtpr_both_absent(name)
}

_pf_elbtpr_both_absent(name) if {
	_pf_elb_absent(name, "Protocol")
	_pf_elb_absent(name, "Port")
}
