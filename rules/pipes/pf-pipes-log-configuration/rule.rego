package cdk_preflight

import rego.v1

# A log level other than OFF needs somewhere to write ("Must provide at least
# 1 log destination in LogConfiguration"), and the S3 destination only speaks
# JSON ("w3c and plain output formats are not supported by Pipes"). Measured
# 2026-09-07, pipes:CreatePipe, us-east-1; Level OFF with no destination is
# accepted.
_pf_pipelog_url := "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-logs.html"

_pf_pipelog_destinations := ["CloudwatchLogsLogDestination", "FirehoseLogDestination", "S3LogDestination"]

violation contains make_diag_full("pf-pipes-log-configuration", "ERROR", name,
	"Properties.LogConfiguration",
	sprintf("LogConfiguration sets Level %s but names no destination; CreatePipe fails with \"Must provide at least 1 log destination in LogConfiguration\"", [lvl]),
	"Add a CloudwatchLogsLogDestination, FirehoseLogDestination or S3LogDestination, or set Level to OFF",
	_pf_pipelog_url) if {
	some name in resources_of_type("AWS::Pipes::Pipe")
	lc := input.resources[name].properties.LogConfiguration
	is_object(lc)
	lvl := object.get(lc, "Level", null)
	is_string(lvl)
	lvl != "OFF"
	every d in _pf_pipelog_destinations {
		object.get(lc, d, "__pf_absent") == "__pf_absent"
	}
}

violation contains make_diag_full("pf-pipes-log-configuration", "ERROR", name,
	"Properties.LogConfiguration.S3LogDestination.OutputFormat",
	sprintf("S3 pipe logs are only written as JSON, but OutputFormat is '%s'; CreatePipe fails with \"w3c and plain output formats are not supported by Pipes\"", [fmt]),
	"Set OutputFormat to json, or drop it",
	_pf_pipelog_url) if {
	some name in resources_of_type("AWS::Pipes::Pipe")
	fmt := resolve(name, "Properties.LogConfiguration.S3LogDestination.OutputFormat")
	is_string(fmt)
	fmt != "json"
}
