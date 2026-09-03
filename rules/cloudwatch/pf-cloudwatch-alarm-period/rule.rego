package cdk_preflight

import rego.v1

# The registry schema types Period as a bare integer; the valid values are
# only in the service ("Period must be 10, 20, 30 or a multiple of 60").
# The same constraint applies inside MetricStat (bench w11, 2026-09-03).
violation contains make_diag_full("pf-cloudwatch-alarm-period", "ERROR", name,
	"Properties.Period",
	sprintf("Period %v is invalid; PutMetricAlarm fails with \"Period must be 10, 20, 30 or a multiple of 60\"", [p]),
	"Use 10, 20, 30, or a multiple of 60 seconds",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudwatch-alarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	p := to_number(resolve(name, "Properties.Period"))
	not p in {10, 20, 30}
	p % 60 != 0
}

violation contains make_diag_full("pf-cloudwatch-alarm-period", "ERROR", name,
	sprintf("Properties.Metrics (MetricStat.Period of query %d)", [i]),
	sprintf("MetricStat Period %v is invalid; PutMetricAlarm fails with \"Period must be 10, 20, 30 or a multiple of 60\"", [p]),
	"Use 10, 20, 30, or a multiple of 60 seconds",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudwatch-alarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	some item in flatten_list(name, "Properties.Metrics")
	i := item.index
	q := item.value
	is_object(q)
	p := object.get(q, ["MetricStat", "Period"], null)
	is_number(p)
	not p in {10, 20, 30}
	p % 60 != 0
}
