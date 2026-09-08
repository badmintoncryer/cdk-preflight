package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-metric-stream-additional-statistic", "ERROR", name,
	sprintf("Properties.StatisticsConfigurations.%d.AdditionalStatistics", [i]),
	sprintf("AdditionalStatistics contains '%s'; PutMetricStream fails with \"Unsupported statistic %s for selected OutputFormat\"", [st, st]),
	"Use a percentile up to p100 (p99, p99.9) or another supported statistic",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricStream.html") if {
	some name in resources_of_type("AWS::CloudWatch::MetricStream")
	some item in flatten_list(name, "Properties.StatisticsConfigurations")
	i := item.index
	cfg := item.value
	is_object(cfg)
	stats := object.get(cfg, "AdditionalStatistics", null)
	is_array(stats)
	some st in stats
	is_string(st)
	not _pf_cwlib_stat_ok(st)
}
