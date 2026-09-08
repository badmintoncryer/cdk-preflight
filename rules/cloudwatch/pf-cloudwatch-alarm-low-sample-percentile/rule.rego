package cdk_preflight

import rego.v1

# Statistic only ever holds a non-percentile (SampleCount/Average/Sum/Minimum/
# Maximum); percentiles live in ExtendedStatistic. So the two properties
# appearing together is the violation.
violation contains make_diag_full("pf-cloudwatch-alarm-low-sample-percentile", "ERROR", name,
	"Properties.EvaluateLowSampleCountPercentile",
	sprintf("EvaluateLowSampleCountPercentile is set alongside Statistic '%s'; PutMetricAlarm fails with \"Option evaluateLowSampleCountPercentile can not be applied with statistic %s.\"", [s, s]),
	"Drop EvaluateLowSampleCountPercentile, or switch the alarm to a percentile via ExtendedStatistic",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	is_string(resolve(name, "Properties.EvaluateLowSampleCountPercentile"))
	s := resolve(name, "Properties.Statistic")
	is_string(s)
}
