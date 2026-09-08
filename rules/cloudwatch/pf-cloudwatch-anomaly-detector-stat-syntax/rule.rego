package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-anomaly-detector-stat-syntax", "ERROR", name,
	"Properties.SingleMetricAnomalyDetector.Stat",
	sprintf("Stat '%s' is not a CloudWatch statistic; PutAnomalyDetector fails with \"failed to satisfy constraint: Member must satisfy regular expression pattern\"", [st]),
	"Use SampleCount, Average, Sum, Minimum, Maximum, IQM, a percentile (p90) or a trimmed statistic (TM90)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutAnomalyDetector.html") if {
	some name in resources_of_type("AWS::CloudWatch::AnomalyDetector")
	st := resolve(name, "Properties.SingleMetricAnomalyDetector.Stat")
	is_string(st)
	not _pf_cwlib_stat_ok(st)
}
