package cdk_preflight

import rego.v1

_pf_sfnex_url := "https://docs.aws.amazon.com/step-functions/latest/dg/choosing-workflow-type.html"

_pf_sfnex_fix := "Switch the state machine to STANDARD, or use Request-Response integrations and Inline Map in the Express workflow"

violation contains make_diag_full("pf-sfn-express-unsupported", "ERROR", name,
	sprintf("%s.Resource", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("EXPRESS state machine: Task state '%s' Resource '%s' uses a %s integration pattern; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Express state machine does not support '%s' service integration\"", [sname, res, pat, pat]),
	_pf_sfnex_fix, _pf_sfnex_url) if {
	_pf_sfnlib_type(name) == "EXPRESS"
	some [name, p, s, sname, st] in _pf_sfnlib_states
	object.get(st, "Type", null) == "Task"
	res := object.get(st, "Resource", null)
	is_string(res)
	some pat in [".sync", ".waitForTaskToken"]
	regex.match(sprintf("[%s](:2)?$", [pat]), res)
}

violation contains make_diag_full("pf-sfn-express-unsupported", "ERROR", name,
	sprintf("%s.Resource", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("EXPRESS state machine: Task state '%s' targets an Activity; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Express state machine does not support Activity ARN\"", [sname]),
	_pf_sfnex_fix, _pf_sfnex_url) if {
	_pf_sfnlib_type(name) == "EXPRESS"
	some [name, p, s, sname, st] in _pf_sfnlib_states
	res := object.get(st, "Resource", null)
	is_string(res)
	regex.match("^arn:[^:]+:states:[^:]+:[^:]+:activity:", res)
}

violation contains make_diag_full("pf-sfn-express-unsupported", "ERROR", name,
	sprintf("%s.%s.ProcessorConfig.Mode", [_pf_sfnlib_path(name, p, sname), key]),
	sprintf("EXPRESS state machine: Map state '%s' runs in DISTRIBUTED mode; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: The field 'Mode' with value 'DISTRIBUTED' is not supported inside 'EXPRESS' state machines\"", [sname]),
	_pf_sfnex_fix, _pf_sfnex_url) if {
	_pf_sfnlib_type(name) == "EXPRESS"
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some key in ["ItemProcessor", "Iterator"]
	proc := object.get(st, key, null)
	is_object(proc)
	object.get(object.get(proc, "ProcessorConfig", {}), "Mode", null) == "DISTRIBUTED"
}
