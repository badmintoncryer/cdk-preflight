package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-cloudwatch-logging-names", "ERROR", name,
	sprintf("%s.CloudWatchLoggingOptions.LogGroupName", [path]),
	"CloudWatch logging is enabled but LogGroupName is not set; the stream create fails with \"CloudWatch Log Group Name is required if CloudWatch Logging is enabled\"",
	"Set LogGroupName and LogStreamName, or disable CloudWatch logging",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_CloudWatchLoggingOptions.html") if {
	some [name, path, c] in _pf_fhlib_prefixed
	o := object.get(c, "CloudWatchLoggingOptions", null)
	is_object(o)
	coerce_to_bool(object.get(o, "Enabled", false)) == true
	object.get(o, "LogGroupName", "__pf_absent") == "__pf_absent"
}
