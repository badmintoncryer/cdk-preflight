package cdk_preflight

import rego.v1

_pf_lekkm_fix := "Drop KafkaMetrics from MetricsConfig for a non-Kafka source"

_pf_lekkm_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-eventsourcemapping-metricsconfig.html"

violation contains make_diag_full("pf-lambda-esm-metrics-kafka-metrics-kafka-only", "ERROR", name,
	"Properties.MetricsConfig.Metrics",
	"MetricsConfig asks for KafkaMetrics on a non-Kafka event source; that metric is only emitted for MSK and self-managed Kafka",
	_pf_lekkm_fix, _pf_lekkm_url) if {
	some name in _pf_lam_esm
	some v in object.get(_pf_lam_obj(_pf_lam_props(name), "MetricsConfig"), "Metrics", [])
	v == "KafkaMetrics"
	_pf_lam_arn_not(name, "kafka")
}
