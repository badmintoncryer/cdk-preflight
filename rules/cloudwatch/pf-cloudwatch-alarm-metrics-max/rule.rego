package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-alarm-metrics-max", "ERROR", name,
	"Properties.Metrics",
	sprintf("The alarm has %d MetricStat queries; PutMetricAlarm fails with \"Too many metrics in alarm, maximum is 10\"", [n]),
	"Keep MetricStat queries to 10 per alarm (math expressions have a separate limit of 10)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	n := count(_pf_cwlib_queries(name, "MetricStat"))
	n > 10
}
