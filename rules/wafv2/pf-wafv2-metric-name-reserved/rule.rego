package cdk_preflight

import rego.v1

_pf_wafmn_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_VisibilityConfig.html"

_pf_wafmn_fix := "Pick another CloudWatch metric name (Default_Action is reserved for the web ACL default action metric)"

violation contains make_diag_full("pf-wafv2-metric-name-reserved", "ERROR", name, "Properties.VisibilityConfig.MetricName",
	"Default_Action is reserved; the create call fails with \"The metric name is not valid.\"",
	_pf_wafmn_fix, _pf_wafmn_url) if {
	some name in _pf_waflib_containers
	resolve(name, "Properties.VisibilityConfig.MetricName") == "Default_Action"
}

violation contains make_diag_full("pf-wafv2-metric-name-reserved", "ERROR", name, sprintf("Properties.Rules[%d].VisibilityConfig.MetricName", [i]),
	"Default_Action is reserved; the create call fails with \"The metric name is not valid.\"",
	_pf_wafmn_fix, _pf_wafmn_url) if {
	some name in _pf_waflib_containers
	rules := _pf_waflib_rules(name)
	some i
	rules[i].VisibilityConfig.MetricName == "Default_Action"
}
