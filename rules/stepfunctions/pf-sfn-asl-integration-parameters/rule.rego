package cdk_preflight

import rego.v1

_pf_sfnip_url := "https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html"

_pf_sfnip_fix := "Add a Parameters (or Arguments) object with the fields the integration requires"

violation contains make_diag_full("pf-sfn-asl-integration-parameters", "ERROR", name,
	_pf_sfnlib_path(name, p, sname),
	sprintf("Task state '%s' calls the %s:%s integration without a Parameters object; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Parameters field is required for resource ARN: arn:aws:states:::%s:%s\"", [sname, svc, api, svc, api]),
	_pf_sfnip_fix, _pf_sfnip_url) if {
	some [name, p, s, sname, st, svc, api] in _pf_sfnlib_integration
	_pf_sfnlib_ql(name, st) == "JSONPath"
	not _pf_sfnlib_has(st, "Parameters")
}

violation contains make_diag_full("pf-sfn-asl-integration-parameters", "ERROR", name,
	_pf_sfnlib_path(name, p, sname),
	sprintf("JSONata Task state '%s' calls the %s:%s integration without an Arguments object; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Arguments field is required for resource ARN: arn:aws:states:::%s:%s\"", [sname, svc, api, svc, api]),
	_pf_sfnip_fix, _pf_sfnip_url) if {
	some [name, p, s, sname, st, svc, api] in _pf_sfnlib_integration
	_pf_sfnlib_ql(name, st) == "JSONata"
	not _pf_sfnlib_has(st, "Arguments")
}

# Required request fields, measured with ValidateStateMachineDefinition on
# 2026-09-05 (a ".$" suffixed key counts as present).
_pf_sfnip_req contains ["lambda", "invoke", "FunctionName"]

_pf_sfnip_req contains ["sqs", "sendMessage", "QueueUrl"]

_pf_sfnip_req contains ["sqs", "sendMessage", "MessageBody"]

_pf_sfnip_req contains ["sns", "publish", "Message"]

_pf_sfnip_req contains ["dynamodb", "putItem", "TableName"]

_pf_sfnip_req contains ["dynamodb", "putItem", "Item"]

_pf_sfnip_req contains ["dynamodb", "getItem", "TableName"]

_pf_sfnip_req contains ["dynamodb", "getItem", "Key"]

_pf_sfnip_req contains ["states", "startExecution", "StateMachineArn"]

_pf_sfnip_req contains ["events", "putEvents", "Entries"]

_pf_sfnip_req contains ["ecs", "runTask", "TaskDefinition"]

_pf_sfnip_req contains ["glue", "startJobRun", "JobName"]

_pf_sfnip_params(st) := prm if {
	prm := object.get(st, "Parameters", null)
	is_object(prm)
}

_pf_sfnip_params(st) := prm if {
	not is_object(object.get(st, "Parameters", null))
	prm := object.get(st, "Arguments", null)
	is_object(prm)
}

violation contains make_diag_full("pf-sfn-asl-integration-parameters", "ERROR", name,
	_pf_sfnlib_path(name, p, sname),
	sprintf("Task state '%s' calls %s:%s without the required field '%s'; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: The field '%s' is required but was missing\"", [sname, svc, base, field, field]),
	_pf_sfnip_fix, _pf_sfnip_url) if {
	some [name, p, s, sname, st, svc, api] in _pf_sfnlib_integration
	base := regex.replace(api, "[.](sync|waitForTaskToken)(:2)?$", "")
	some [s2, b2, field] in _pf_sfnip_req
	s2 == svc
	b2 == base
	prm := _pf_sfnip_params(st)
	not _pf_sfnlib_has(prm, field)
	not _pf_sfnlib_has(prm, sprintf("%s.$", [field]))
}
