package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-metric-stream-include-metrics", "ERROR", name,
	sprintf("Properties.StatisticsConfigurations.%d.IncludeMetrics", [i]),
	sprintf("StatisticsConfigurations[%d] has an empty IncludeMetrics; PutMetricStream fails with \"IncludeMetrics less than 1\"", [i]),
	"List the metrics the additional statistics apply to, or drop the statistics configuration",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricStream.html") if {
	some name in resources_of_type("AWS::CloudWatch::MetricStream")
	some item in flatten_list(name, "Properties.StatisticsConfigurations")
	i := item.index
	cfg := item.value
	is_object(cfg)
	metrics := object.get(cfg, "IncludeMetrics", null)
	is_array(metrics)
	count(metrics) == 0
}
