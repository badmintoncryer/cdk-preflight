package cdk_preflight

import rego.v1

_pf_elbrcd_fix := "Merge the values into one condition of that field"

_pf_elbrcd_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RuleCondition.html"

_pf_elbrcd_once := {"host-header", "path-pattern", "http-request-method", "source-ip"}

violation contains make_diag_full("pf-elbv2-rule-condition-duplicate-field", "ERROR", name,
	"Properties.Conditions",
	sprintf("A rule can only have one '%s' condition; this rule has %d", [f, n]),
	_pf_elbrcd_fix, _pf_elbrcd_url) if {
	some name in _pf_elb_rules
	some f in _pf_elbrcd_once
	n := count([c | some c in _pf_elb_conditions(name); object.get(c.value, "Field", "") == f])
	n > 1
}
