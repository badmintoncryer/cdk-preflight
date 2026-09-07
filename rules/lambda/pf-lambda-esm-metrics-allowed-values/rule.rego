package cdk_preflight

import rego.v1

_pf_lemav_fix := "Use EventCount, ErrorCount or KafkaMetrics"

_pf_lemav_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-eventsourcemapping-metricsconfig.html"

_pf_lemav_ok := {"EventCount", "ErrorCount", "KafkaMetrics"}

violation contains make_diag_full("pf-lambda-esm-metrics-allowed-values", "ERROR", name,
	"Properties.MetricsConfig.Metrics",
	sprintf("MetricsConfig.Metrics lists '%v'; the accepted values are EventCount, ErrorCount and KafkaMetrics", [v]),
	_pf_lemav_fix, _pf_lemav_url) if {
	some name in _pf_lam_esm
	l := object.get(_pf_lam_obj(_pf_lam_props(name), "MetricsConfig"), "Metrics", [])
	is_array(l)
	some v in l
	is_string(v)
	not v in _pf_lemav_ok
}
