package cdk_preflight

import rego.v1

_pf_elbrcr_fix := "Add a condition (only the listener default action runs without one)"

_pf_elbrcr_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RuleCondition.html"

violation contains make_diag_full("pf-elbv2-rule-conditions-required", "ERROR", name,
	"Properties.Conditions",
	"A condition must be specified; only the listener's default action matches every request",
	_pf_elbrcr_fix, _pf_elbrcr_url) if {
	some name in _pf_elb_rules
	count(_pf_elb_conditions(name)) == 0
}
