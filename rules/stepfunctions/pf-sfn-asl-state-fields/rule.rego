package cdk_preflight

import rego.v1

_pf_sfnfld_url := "https://docs.aws.amazon.com/step-functions/latest/dg/statemachine-structure.html"

_pf_sfnfld_fix := "Remove the field or move the logic to a state type that supports it (see the ASL state pages)"

# Measured with ValidateStateMachineDefinition on 2026-09-05 (8 types x 50
# fields). Type/Comment/QueryLanguage are accepted everywhere.
_pf_sfnfld_common := {"Type", "Comment", "QueryLanguage"}

_pf_sfnfld_allowed := {
	"Pass": {"InputPath", "OutputPath", "Result", "ResultPath", "Parameters", "Output", "Assign", "Next", "End"},
	"Task": {"InputPath", "OutputPath", "ResultPath", "Parameters", "Arguments", "Output", "Assign", "Resource", "Credentials", "ResultSelector", "Retry", "Catch", "TimeoutSeconds", "TimeoutSecondsPath", "HeartbeatSeconds", "HeartbeatSecondsPath", "Next", "End"},
	"Wait": {"InputPath", "OutputPath", "Output", "Assign", "Seconds", "Timestamp", "SecondsPath", "TimestampPath", "Next", "End"},
	"Parallel": {"InputPath", "OutputPath", "ResultPath", "Parameters", "Arguments", "Output", "Assign", "ResultSelector", "Retry", "Catch", "Branches", "Next", "End"},
	"Map": {"InputPath", "OutputPath", "ResultPath", "Parameters", "Output", "Assign", "ResultSelector", "Retry", "Catch", "ItemProcessor", "Iterator", "ItemsPath", "Items", "ItemSelector", "ItemReader", "ItemBatcher", "ResultWriter", "MaxConcurrency", "MaxConcurrencyPath", "ToleratedFailurePercentage", "ToleratedFailurePercentagePath", "ToleratedFailureCount", "ToleratedFailureCountPath", "Label", "Next", "End"},
	"Choice": {"InputPath", "OutputPath", "Output", "Assign", "Choices", "Default"},
	"Succeed": {"InputPath", "OutputPath", "Output"},
	"Fail": {"Error", "Cause", "ErrorPath", "CausePath"},
}

_pf_sfnfld_known := {f | some _, fs in _pf_sfnfld_allowed; some f in fs} | _pf_sfnfld_common

# ponytail: only fields the service already knows are judged; a field that no
# type accepts is left alone because it may be a newer ASL feature rather than
# a typo (a false positive here would block valid deploys). Case variants of a
# known field (ASL is case-sensitive) are judged too.
violation contains make_diag_full("pf-sfn-asl-state-fields", "ERROR", name,
	sprintf("%s.%s", [_pf_sfnlib_path(name, p, sname), f]),
	sprintf("state '%s' (Type %s) has field '%s', which Step Functions does not accept on that state type; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Field '%s' is not supported\"", [sname, t, f, f]),
	_pf_sfnfld_fix, _pf_sfnfld_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	t := object.get(st, "Type", null)
	allowed := _pf_sfnfld_allowed[t]
	some f, _ in st
	not f in _pf_sfnfld_common
	not f in allowed
	f in _pf_sfnfld_known
}

violation contains make_diag_full("pf-sfn-asl-state-fields", "ERROR", name,
	sprintf("%s.%s", [_pf_sfnlib_path(name, p, sname), f]),
	sprintf("state '%s' has field '%s'; ASL field names are case-sensitive (did you mean '%s'?), and CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Field '%s' is not supported\"", [sname, f, k, f]),
	_pf_sfnfld_fix, _pf_sfnfld_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some f, _ in st
	not f in _pf_sfnfld_known
	some k in _pf_sfnfld_known
	lower(k) == lower(f)
}

_pf_sfnfld_top := {"Comment", "QueryLanguage", "StartAt", "TimeoutSeconds", "Version", "States"}

violation contains make_diag_full("pf-sfn-asl-state-fields", "ERROR", name,
	sprintf("%s.%s", [_pf_sfnlib_prop(name), f]),
	sprintf("top-level field '%s' is not an ASL field (did you mean '%s'?); CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Field '%s' is not supported\"", [f, k, f]),
	_pf_sfnfld_fix, _pf_sfnfld_url) if {
	some name in resources_of_type("AWS::StepFunctions::StateMachine")
	asl := _pf_sfnlib_asl(name)
	some f, _ in asl
	not f in _pf_sfnfld_top
	some k in _pf_sfnfld_top
	lower(k) == lower(f)
}

violation contains make_diag_full("pf-sfn-asl-state-fields", "ERROR", name,
	sprintf("%s.Version", [_pf_sfnlib_prop(name)]),
	sprintf("ASL Version '%s' is not supported; the only accepted value is \"1.0\" (CreateStateMachine: \"SCHEMA_VALIDATION_FAILED: Value should be one of the following: [1.0]\")", [v]),
	_pf_sfnfld_fix, _pf_sfnfld_url) if {
	some name in resources_of_type("AWS::StepFunctions::StateMachine")
	v := object.get(_pf_sfnlib_asl(name), "Version", null)
	is_string(v)
	v != "1.0"
}
