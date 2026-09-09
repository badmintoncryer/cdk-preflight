package cdk_preflight

import rego.v1

_pf_elbrnh_fix := "Use a host-header condition instead of an http-header condition on Host"

_pf_elbrnh_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RuleCondition.html"

violation contains make_diag_full("pf-elbv2-rule-http-header-not-host", "ERROR", name,
	sprintf("Properties.Conditions.%d.HttpHeaderConfig.HttpHeaderName", [c.index]),
	"You cannot specify 'host' as an HTTP header name; the load balancer routes on the Host header through a host-header condition",
	_pf_elbrnh_fix, _pf_elbrnh_url) if {
	some name in _pf_elb_rules
	some c in _pf_elb_conditions(name)
	h := _pf_elb_oget(_pf_elb_cond_cfg(c.value), "HttpHeaderName")
	is_string(h)
	lower(h) == "host"
}
