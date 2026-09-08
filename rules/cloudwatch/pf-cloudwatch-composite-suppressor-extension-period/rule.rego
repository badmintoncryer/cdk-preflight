package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudwatch-composite-suppressor-extension-period", "ERROR", name,
	"Properties.ActionsSuppressorExtensionPeriod",
	"ActionsSuppressor is set without ActionsSuppressorExtensionPeriod; PutCompositeAlarm fails with \"ActionsSuppressorExtensionPeriod must not be null\"",
	"Set ActionsSuppressorExtensionPeriod (seconds to keep suppressing after the suppressor alarm clears)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutCompositeAlarm.html") if {
	some name in resources_of_type("AWS::CloudWatch::CompositeAlarm")
	is_string(resolve(name, "Properties.ActionsSuppressor"))
	_pf_cwlib_absent(name, "ActionsSuppressorExtensionPeriod")
}
