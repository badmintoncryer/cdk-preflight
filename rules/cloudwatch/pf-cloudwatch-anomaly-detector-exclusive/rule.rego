package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-anomaly-detector-exclusive", "ERROR", name,
	"Properties.MetricMathAnomalyDetector",
	"The detector sets both SingleMetricAnomalyDetector and MetricMathAnomalyDetector; PutAnomalyDetector fails with \"Either single metric attributes, SingleMetricAnomalyDetector or MetricMathAnomalyDetector can be set\"",
	"Keep one detector definition",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutAnomalyDetector.html") if {
	some name in resources_of_type("AWS::CloudWatch::AnomalyDetector")
	not _pf_cwlib_absent(name, "SingleMetricAnomalyDetector")
	not _pf_cwlib_absent(name, "MetricMathAnomalyDetector")
}
