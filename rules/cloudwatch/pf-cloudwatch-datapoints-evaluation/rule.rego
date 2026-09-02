package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-datapoints-evaluation", "ERROR", name,
	"Properties.DatapointsToAlarm",
	sprintf("DatapointsToAlarm (%v) exceeds EvaluationPeriods (%v); PutMetricAlarm fails with \"DatapointsToAlarm must be less than or equal to EvaluationPeriods\"", [d, ev]),
	"Lower DatapointsToAlarm to at most EvaluationPeriods, or raise EvaluationPeriods",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudwatch-alarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	d := to_number(resolve(name, "Properties.DatapointsToAlarm"))
	ev := to_number(resolve(name, "Properties.EvaluationPeriods"))
	d > ev
}
