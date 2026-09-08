package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-composite-suppressor-wait-period", "ERROR", name,
	"Properties.ActionsSuppressorWaitPeriod",
	"ActionsSuppressor is set without ActionsSuppressorWaitPeriod; PutCompositeAlarm fails with \"ActionsSuppressorWaitPeriod must not be null\"",
	"Set ActionsSuppressorWaitPeriod (seconds to wait for the suppressor alarm to go into ALARM)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutCompositeAlarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::CompositeAlarm")
	is_string(resolve(name, "Properties.ActionsSuppressor"))
	_pf_cwlib_absent(name, "ActionsSuppressorWaitPeriod")
}
