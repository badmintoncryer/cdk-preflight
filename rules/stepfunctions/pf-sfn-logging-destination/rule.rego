package cdk_preflight

import rego.v1

_pf_sfnlog_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-stepfunctions-statemachine-loggingconfiguration.html"

_pf_sfnlog_fix := "Reference the log group with Fn::GetAtt LogGroup.Arn (it already ends in :*) in a single Destinations entry"

# An empty Destinations array is stopped by the schema (F3032 minItems);
# the absent-while-enabled and two-entries cases are not.
_pf_sfnlog_on(name) if {
	lvl := resolve(name, "Properties.LoggingConfiguration.Level")
	is_string(lvl)
	lvl != "OFF"
}

violation contains make_diag_full("pf-sfn-logging-destination", "ERROR", name,
	"Properties.LoggingConfiguration.Destinations",
	sprintf("LoggingConfiguration has %d Destinations entries while Level is not OFF; exactly one is required, and CreateStateMachine fails with \"InvalidLoggingConfiguration: Must specify exactly one Log Destination.\"", [n]),
	_pf_sfnlog_fix, _pf_sfnlog_url) if {
	some name in resources_of_type("AWS::StepFunctions::StateMachine")
	_pf_sfnlog_on(name)
	n := count(flatten_list(name, "Properties.LoggingConfiguration.Destinations"))
	n != 1
}

violation contains make_diag_full("pf-sfn-logging-destination", "ERROR", name,
	sprintf("Properties.LoggingConfiguration.Destinations.%d", [d.index]),
	"a Destinations entry has no CloudWatchLogsLogGroup; CreateStateMachine fails with \"InvalidLoggingConfiguration: Must set valid CloudWatch Log Group ARN.\"",
	_pf_sfnlog_fix, _pf_sfnlog_url) if {
	some name in resources_of_type("AWS::StepFunctions::StateMachine")
	_pf_sfnlog_on(name)
	some d in flatten_list(name, "Properties.LoggingConfiguration.Destinations")
	is_object(d.value)
	not _pf_sfnlib_has(d.value, "CloudWatchLogsLogGroup")
}

_pf_sfnlog_arn contains [name, idx, arn] if {
	some name in resources_of_type("AWS::StepFunctions::StateMachine")
	_pf_sfnlog_on(name)
	some d in flatten_list(name, "Properties.LoggingConfiguration.Destinations")
	is_object(d.value)
	arn := object.get(object.get(d.value, "CloudWatchLogsLogGroup", {}), "LogGroupArn", null)
	is_string(arn)
	startswith(arn, "arn:")
	idx := d.index
}

violation contains make_diag_full("pf-sfn-logging-destination", "ERROR", name,
	sprintf("Properties.LoggingConfiguration.Destinations.%d.CloudWatchLogsLogGroup.LogGroupArn", [idx]),
	sprintf("LogGroupArn '%s' is not a CloudWatch Logs log-group ARN; CreateStateMachine fails with \"InvalidLoggingConfiguration: Provided ARN is not CloudWatch Logs Log Group ARN.\"", [arn]),
	_pf_sfnlog_fix, _pf_sfnlog_url) if {
	some [name, idx, arn] in _pf_sfnlog_arn
	not regex.match("^arn:[^:]+:logs:[^:]*:[^:]*:log-group:", arn)
}

violation contains make_diag_full("pf-sfn-logging-destination", "ERROR", name,
	sprintf("Properties.LoggingConfiguration.Destinations.%d.CloudWatchLogsLogGroup.LogGroupArn", [idx]),
	sprintf("LogGroupArn '%s' lacks the :* qualifier (Fn::GetAtt LogGroup.Arn includes it); CreateStateMachine fails with \"InvalidLoggingConfiguration: Log Group ARN must be provided with '*' qualifier.\"", [arn]),
	_pf_sfnlog_fix, _pf_sfnlog_url) if {
	some [name, idx, arn] in _pf_sfnlog_arn
	regex.match("^arn:[^:]+:logs:[^:]*:[^:]*:log-group:", arn)
	not endswith(arn, ":*")
}
