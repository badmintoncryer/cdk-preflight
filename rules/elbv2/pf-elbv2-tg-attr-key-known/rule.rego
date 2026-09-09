package cdk_preflight

import rego.v1

_pf_elbgkk_fix := "Use a key from the TargetGroupAttribute table (a typo is rejected, not ignored)"

_pf_elbgkk_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

violation contains make_diag_full("pf-elbv2-tg-attr-key-known", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Key", [p.index]),
	sprintf("Target group attribute key '%s' is not recognized; ModifyTargetGroupAttributes rejects unknown keys", [p.key]),
	_pf_elbgkk_fix, _pf_elbgkk_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	not p.key in _pf_elb_tgattr_known
}
