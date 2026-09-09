package cdk_preflight

import rego.v1

_pf_elbgdup_fix := "Keep one entry per attribute key"

_pf_elbgdup_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

violation contains make_diag_full("pf-elbv2-tg-attr-duplicate-key", "ERROR", name,
	"Properties.TargetGroupAttributes",
	sprintf("Attribute key '%s' is specified more than once; ModifyTargetGroupAttributes fails with \"Attribute key '%s' has been specified more than once\"", [k, k]),
	_pf_elbgdup_fix, _pf_elbgdup_url) if {
	some name in _pf_elb_tgs
	keys := [x.key | some x in _pf_elb_pairs(name, "TargetGroupAttributes")]
	some k in keys
	count([x | some x in keys; x == k]) > 1
}
