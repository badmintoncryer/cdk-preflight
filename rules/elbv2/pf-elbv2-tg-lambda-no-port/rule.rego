package cdk_preflight

import rego.v1

_pf_elbtlp_fix := "Drop Port; a Lambda target is invoked, not connected to"

_pf_elbtlp_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-lambda-no-port", "ERROR", name,
	"Properties.Port",
	"Port is set on a lambda target group; CreateTargetGroup rejects a protocol or port for target type 'lambda'",
	_pf_elbtlp_fix, _pf_elbtlp_url) if {
	some name in _pf_elb_tgs
	_pf_elb_tgtype(name) == "lambda"
	_pf_elb_has(name, "Port")
}
