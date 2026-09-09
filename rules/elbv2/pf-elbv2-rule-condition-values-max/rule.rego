package cdk_preflight

import rego.v1

_pf_elbrcv_fix := "Keep the condition values (and regex values) of the whole rule to five, or split the rule"

_pf_elbrcv_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-update-rules.html"

violation contains make_diag_full("pf-elbv2-rule-condition-values-max", "ERROR", name,
	"Properties.Conditions",
	sprintf("A rule can only have '5' condition values and regex values; this rule has %d", [n]),
	_pf_elbrcv_fix, _pf_elbrcv_url) if {
	some name in _pf_elb_rules
	n := sum([count(_pf_elb_cond_values(c.value)) | some c in _pf_elb_conditions(name)])
	n > 5
}
