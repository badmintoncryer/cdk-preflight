package cdk_preflight

import rego.v1

_pf_sfncred_url := "https://docs.aws.amazon.com/step-functions/latest/dg/state-task.html"

_pf_sfncred_fix := "Set Credentials.RoleArn (or RoleArn.$); drop Credentials from activity tasks"

violation contains make_diag_full("pf-sfn-asl-credentials", "ERROR", name,
	sprintf("%s.Credentials", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("Task state '%s' has Credentials without RoleArn; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: The field 'RoleArn' is required but was missing\"", [sname]),
	_pf_sfncred_fix, _pf_sfncred_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	cred := object.get(st, "Credentials", null)
	is_object(cred)
	not _pf_sfnlib_has(cred, "RoleArn")
	not _pf_sfnlib_has(cred, "RoleArn.$")
}

violation contains make_diag_full("pf-sfn-asl-credentials", "ERROR", name,
	sprintf("%s.Credentials", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("Task state '%s' sets Credentials on an Activity resource; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: The field 'Credentials' is not supported for activities\"", [sname]),
	_pf_sfncred_fix, _pf_sfncred_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	_pf_sfnlib_has(st, "Credentials")
	res := object.get(st, "Resource", null)
	is_string(res)
	regex.match("^arn:[^:]+:states:[^:]+:[^:]+:activity:", res)
}
