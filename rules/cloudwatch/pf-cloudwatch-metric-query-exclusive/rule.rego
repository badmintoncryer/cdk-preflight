package cdk_preflight

import rego.v1

# One query entry is either a math expression or a metric fetch, never both.
# The specify-neither shape fails too, but with an unrelated error ("Period
# must not be null", bench w03b) — so only the both-set direction is claimed.
violation contains make_diag_full("pf-cloudwatch-metric-query-exclusive", "ERROR", name,
	sprintf("Properties.Metrics.%d", [q.index]),
	sprintf("Metric query '%s' sets both Expression and MetricStat; PutMetricAlarm fails with \"The parameters MetricDataQuery Expression and MetricStat are mutually exclusive and you have specified both.\"", [qid]),
	"Keep the Expression and drop MetricStat (fetch the inputs in separate queries), or vice versa",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudwatch-alarm-metricdataquery.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	some q in flatten_list(name, "Properties.Metrics")
	is_object(q.value)
	object.get(q.value, "Expression", "__pf_absent") != "__pf_absent"
	object.get(q.value, "MetricStat", "__pf_absent") != "__pf_absent"
	qid := object.get(q.value, "Id", "<query>")
}
