package cdk_preflight

import rego.v1

_pf_elbgks_fix := "Keep protocol-only attributes on a target group of that protocol family"

_pf_elbgks_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

# これらのキーは専用ルールが担当する（重複して鳴らせない）
_pf_elbgks_owned := {
	"slow_start.duration_seconds", "lambda.multi_value_headers.enabled",
	"deregistration_delay.timeout_seconds",
	"send_tcp_reset.on_unhealthy.enabled", "send_tcp_reset.on_deregistration.enabled",
}

violation contains make_diag_full("pf-elbv2-tg-attr-key-protocol-scope", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Key", [p.index]),
	sprintf("Attribute key '%s' is not supported on a %s target group; ModifyTargetGroupAttributes reports it as not recognized", [p.key, f]),
	_pf_elbgks_fix, _pf_elbgks_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	f := _pf_elb_tgfamily(name)
	p.key in _pf_elb_tgattr_known
	not p.key in _pf_elbgks_owned
	not p.key in _pf_elb_tgattr_for[f]
}
