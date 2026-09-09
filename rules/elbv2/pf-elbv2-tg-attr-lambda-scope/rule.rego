package cdk_preflight

import rego.v1

_pf_elbgls_fix := "Drop lambda.multi_value_headers.enabled unless TargetType is lambda"

_pf_elbgls_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

violation contains make_diag_full("pf-elbv2-tg-attr-lambda-scope", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Key", [p.index]),
	sprintf("lambda.multi_value_headers.enabled is set on a '%s' target group; it only applies to a lambda target group", [t]),
	_pf_elbgls_fix, _pf_elbgls_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	p.key == "lambda.multi_value_headers.enabled"
	t := _pf_elb_tgtype(name)
	t != "lambda"
}
