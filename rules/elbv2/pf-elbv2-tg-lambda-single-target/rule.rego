package cdk_preflight

import rego.v1

_pf_elbtl1_fix := "Register one function per target group (this quota cannot be raised)"

_pf_elbtl1_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-lambda-single-target", "ERROR", name,
	"Properties.Targets",
	sprintf("%d targets are registered on a lambda target group; RegisterTargets answers \"Up to '1' Lambda function target(s) can be registered, but '%d' were specified\"", [n, n]),
	_pf_elbtl1_fix, _pf_elbtl1_url) if {
	some name in _pf_elb_tgs
	_pf_elb_tgtype(name) == "lambda"
	n := count(flatten_list(name, "Properties.Targets"))
	n > 1
}
