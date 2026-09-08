package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-metricstat-stat-syntax", "ERROR", name,
	sprintf("Properties.Metrics (MetricStat.Stat of query %d)", [i]),
	sprintf("MetricStat Stat '%s' is not a CloudWatch statistic; PutMetricAlarm fails with \"Invalid metrics list\"", [st]),
	"Use SampleCount, Average, Sum, Minimum, Maximum, IQM, a percentile (p90) or a trimmed statistic (TM90)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	some item in flatten_list(name, "Properties.Metrics")
	i := item.index
	q := item.value
	is_object(q)
	st := object.get(q, ["MetricStat", "Stat"], null)
	is_string(st)
	not _pf_cwlib_stat_ok(st)
}
