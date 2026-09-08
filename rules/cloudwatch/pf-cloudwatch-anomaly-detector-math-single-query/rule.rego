package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-anomaly-detector-math-single-query", "ERROR", name,
	"Properties.MetricMathAnomalyDetector.MetricDataQueries",
	"The math detector has one metric data query; PutAnomalyDetector fails with \"The MetricDataQueries list in MetricMathAnomalyDetector contains a single metric, please use SingleMetricAnomalyDetector instead\"",
	"Use SingleMetricAnomalyDetector for one metric, or add the math expression query",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutAnomalyDetector.html") if {
	some name in resources_of_type("AWS::CloudWatch::AnomalyDetector")
	items := [q | some q in flatten_list(name, "Properties.MetricMathAnomalyDetector.MetricDataQueries")]
	count(items) == 1
}
