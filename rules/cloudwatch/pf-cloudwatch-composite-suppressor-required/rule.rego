package cdk_preflight

import rego.v1

_pf_cwsr_periods := {"ActionsSuppressorWaitPeriod", "ActionsSuppressorExtensionPeriod"}

violation contains make_diag_full("pf-cloudwatch-composite-suppressor-required", "ERROR", name,
	sprintf("Properties.%s", [key]),
	sprintf("%s is set but ActionsSuppressor is not; PutCompositeAlarm fails with \"%s requires an ActionSuppressor\"", [key, key]),
	"Set ActionsSuppressor to the alarm that should suppress actions, or drop the suppressor periods",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutCompositeAlarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::CompositeAlarm")
	some key in _pf_cwsr_periods
	not _pf_cwlib_absent(name, key)
	_pf_cwlib_absent(name, "ActionsSuppressor")
}
