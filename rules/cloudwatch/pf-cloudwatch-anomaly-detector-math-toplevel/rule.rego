package cdk_preflight

import rego.v1

_pf_cwmt_single := {"MetricName", "Namespace", "Stat", "Dimensions"}

violation contains make_diag_full("pf-cloudwatch-anomaly-detector-math-toplevel", "ERROR", name,
	sprintf("Properties.%s", [key]),
	sprintf("MetricMathAnomalyDetector is set alongside the top-level %s; PutAnomalyDetector fails with \"Either single metric attributes, SingleMetricAnomalyDetector or MetricMathAnomalyDetector can be set\"", [key]),
	"Move the metric into the MetricDataQueries, or drop MetricMathAnomalyDetector",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutAnomalyDetector.html") if {
	some name in resources_of_type("AWS::CloudWatch::AnomalyDetector")
	not _pf_cwlib_absent(name, "MetricMathAnomalyDetector")
	some key in _pf_cwmt_single
	not _pf_cwlib_absent(name, key)
}
