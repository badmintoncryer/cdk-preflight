package cdk_preflight

import rego.v1

# Two tiers, both measured: a week for hourly-or-longer periods, a day below
# that. Issue #6 recorded this as BROKEN-EXPECTATION after testing 3600 x 100,
# which is inside the 604800 budget - the probe was aimed wrong, not the doc.
_pf_cwew_limit(p) := 604800 if p >= 3600

_pf_cwew_limit(p) := 86400 if p < 3600

violation contains make_diag_full("pf-cloudwatch-alarm-evaluation-window", "ERROR", name,
	"Properties.EvaluationPeriods",
	sprintf("Period %v x EvaluationPeriods %v spans %v seconds; PutMetricAlarm fails with \"EvaluationPeriods * Period must be <= %v\"", [p, e, p * e, lim]),
	"Shorten the window: EvaluationPeriods x Period must stay within 604800 seconds when Period >= 3600, and within 86400 seconds when Period < 3600",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::Alarm")
	p := to_number(resolve(name, "Properties.Period"))
	e := to_number(resolve(name, "Properties.EvaluationPeriods"))
	lim := _pf_cwew_limit(p)
	p * e > lim
}
