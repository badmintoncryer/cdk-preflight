package cdk_preflight

import rego.v1

_pf_elbtmra_fix := "Keep Matcher.HttpCode inside 200-499"

_pf_elbtmra_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-matcher-range-alb", "ERROR", name,
	"Properties.Matcher.HttpCode",
	sprintf("Matcher.HttpCode '%s' includes %v, outside the accepted range 200-499", [code, n]),
	_pf_elbtmra_fix, _pf_elbtmra_url) if {
	some name in _pf_elb_tgs
	_pf_elb_str(name, "Protocol") in _pf_elb_alb_protocols
	code := resolve(name, "Properties.Matcher.HttpCode")
	is_string(code)
	some n in _pf_elb_codes(code)
	_pf_elb_outside(n, 200, 499)
}
