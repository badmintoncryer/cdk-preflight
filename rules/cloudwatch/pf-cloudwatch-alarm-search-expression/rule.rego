package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-alarm-search-expression", "ERROR", name,
	sprintf("Properties.Metrics (Expression of query %d)", [i]),
	"A SEARCH() expression cannot back an alarm; PutMetricAlarm fails with \"SEARCH is not supported on Metric Alarms.\"",
	"Name the metrics explicitly with MetricStat queries, or build the alarm from a math expression over them",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	some item in flatten_list(name, "Properties.Metrics")
	i := item.index
	q := item.value
	is_object(q)
	e := object.get(q, "Expression", null)
	is_string(e)
	regex.match(`(?i)\bSEARCH\s*\(`, e)
}
