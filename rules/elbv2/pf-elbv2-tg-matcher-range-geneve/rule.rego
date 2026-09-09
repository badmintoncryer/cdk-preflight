package cdk_preflight

import rego.v1

_pf_elbtmrg_fix := "Keep Matcher.HttpCode inside 200-399"

_pf_elbtmrg_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-matcher-range-geneve", "ERROR", name,
	"Properties.Matcher.HttpCode",
	sprintf("Matcher.HttpCode '%s' includes %v; a GENEVE target group only accepts 200-399", [code, n]),
	_pf_elbtmrg_fix, _pf_elbtmrg_url) if {
	some name in _pf_elb_tgs
	_pf_elb_str(name, "Protocol") == "GENEVE"
	code := resolve(name, "Properties.Matcher.HttpCode")
	is_string(code)
	some n in _pf_elb_codes(code)
	_pf_elb_outside(n, 200, 399)
}
