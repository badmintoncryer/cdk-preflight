package cdk_preflight

import rego.v1

_pf_sfnql_url := "https://docs.aws.amazon.com/step-functions/latest/dg/transforming-data.html"

_pf_sfnql_fix := "Use Arguments/Output/Items/Condition in JSONata states and the Path-style fields in JSONPath states; set QueryLanguage consistently"

_pf_sfnql_pathonly := {"InputPath", "OutputPath", "ResultPath", "Parameters", "ResultSelector", "Result", "ItemsPath", "TimeoutSecondsPath", "HeartbeatSecondsPath", "SecondsPath", "TimestampPath", "MaxConcurrencyPath", "ToleratedFailurePercentagePath", "ToleratedFailureCountPath", "ErrorPath", "CausePath"}

_pf_sfnql_jsonataonly := {"Arguments", "Output", "Items"}

violation contains make_diag_full("pf-sfn-asl-query-language", "ERROR", name,
	sprintf("%s.%s", [_pf_sfnlib_path(name, p, sname), f]),
	sprintf("state '%s' uses JSONata but has the JSONPath-only field '%s'; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: The QueryLanguage is set to 'JSONata', but field '%s' is only supported for the 'JSONPath' QueryLanguage\"", [sname, f, f]),
	_pf_sfnql_fix, _pf_sfnql_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	_pf_sfnlib_ql(name, st) == "JSONata"
	some f, _ in st
	f in _pf_sfnql_pathonly
}

violation contains make_diag_full("pf-sfn-asl-query-language", "ERROR", name,
	sprintf("%s.%s", [_pf_sfnlib_path(name, p, sname), f]),
	sprintf("state '%s' uses JSONPath but has the JSONata-only field '%s'; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: The QueryLanguage is set to 'JSONPath', but field '%s' is only supported for the 'JSONata' QueryLanguage\"", [sname, f, f]),
	_pf_sfnql_fix, _pf_sfnql_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	_pf_sfnlib_ql(name, st) == "JSONPath"
	some f, _ in st
	f in _pf_sfnql_jsonataonly
}

violation contains make_diag_full("pf-sfn-asl-query-language", "ERROR", name,
	sprintf("%s.Choices[%d]", [_pf_sfnlib_path(name, p, sname), i]),
	sprintf("Choice state '%s' rule %d uses Variable/comparison fields in a JSONata state; JSONata rules take Condition, and CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: ... field 'Variable' is only supported for the 'JSONPath' QueryLanguage\"", [sname, i]),
	_pf_sfnql_fix, _pf_sfnql_url) if {
	some [name, p, s, sname, i, c] in _pf_sfnlib_choice
	st := s[sname]
	_pf_sfnlib_ql(name, st) == "JSONata"
	_pf_sfnlib_has(c, "Variable")
}

violation contains make_diag_full("pf-sfn-asl-query-language", "ERROR", name,
	sprintf("%s.Choices[%d]", [_pf_sfnlib_path(name, p, sname), i]),
	sprintf("Choice state '%s' rule %d uses Condition in a JSONPath state; JSONPath rules take Variable plus a comparison, and CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: ... field 'Condition' is only supported for the 'JSONata' QueryLanguage\"", [sname, i]),
	_pf_sfnql_fix, _pf_sfnql_url) if {
	some [name, p, s, sname, i, c] in _pf_sfnlib_choice
	st := s[sname]
	_pf_sfnlib_ql(name, st) == "JSONPath"
	_pf_sfnlib_has(c, "Condition")
}

violation contains make_diag_full("pf-sfn-asl-query-language", "ERROR", name,
	sprintf("%s.QueryLanguage", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("state '%s' sets QueryLanguage JSONPath inside a state machine whose top-level QueryLanguage is JSONata; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: 'QueryLanguage' can not be 'JSONPath' if set to 'JSONata' for whole state machine\"", [sname]),
	_pf_sfnql_fix, _pf_sfnql_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	object.get(_pf_sfnlib_asl(name), "QueryLanguage", null) == "JSONata"
	object.get(st, "QueryLanguage", null) == "JSONPath"
}

violation contains make_diag_full("pf-sfn-asl-query-language", "ERROR", name,
	sprintf("%s.QueryLanguage", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("state '%s' QueryLanguage '%s' is not JSONPath or JSONata; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Value should be one of the following: [JSONPath, JSONata]\"", [sname, q]),
	_pf_sfnql_fix, _pf_sfnql_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	q := object.get(st, "QueryLanguage", null)
	is_string(q)
	not q in {"JSONPath", "JSONata"}
}

violation contains make_diag_full("pf-sfn-asl-query-language", "ERROR", name,
	sprintf("%s.QueryLanguage", [_pf_sfnlib_prop(name)]),
	sprintf("top-level QueryLanguage '%s' is not JSONPath or JSONata; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Value should be one of the following: [JSONPath, JSONata]\"", [q]),
	_pf_sfnql_fix, _pf_sfnql_url) if {
	some name in resources_of_type("AWS::StepFunctions::StateMachine")
	q := object.get(_pf_sfnlib_asl(name), "QueryLanguage", null)
	is_string(q)
	not q in {"JSONPath", "JSONata"}
}

# String values of a JSONata state, up to two levels inside object/array
# fields (Arguments, Output, Assign, ItemSelector, Choices[].Condition ...).
_pf_sfnql_str contains [name, p, sname, where, v] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	_pf_sfnlib_ql(name, st) == "JSONata"
	some f, v in st
	is_string(v)
	where := f
}

# Iterating a scalar with `some .. in` is a hard evaluation error in this
# engine (not undefined), so every nested value is type-guarded first.
_pf_sfnql_coll(x) if is_object(x)

_pf_sfnql_coll(x) if is_array(x)

_pf_sfnql_str contains [name, p, sname, where, v] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	_pf_sfnlib_ql(name, st) == "JSONata"
	some f, o in st
	_pf_sfnql_coll(o)
	some k, v in o
	is_string(v)
	where := sprintf("%s.%v", [f, k])
}

_pf_sfnql_str contains [name, p, sname, where, v] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	_pf_sfnlib_ql(name, st) == "JSONata"
	some f, o in st
	_pf_sfnql_coll(o)
	some k, o2 in o
	_pf_sfnql_coll(o2)
	some k2, v in o2
	is_string(v)
	where := sprintf("%s.%v.%v", [f, k, k2])
}

violation contains make_diag_full("pf-sfn-asl-query-language", "ERROR", name,
	sprintf("%s.%s", [_pf_sfnlib_path(name, p, sname), where]),
	sprintf("state '%s' %s value '%s' opens a JSONata expression with {%% but does not close it with %%}; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: JSONata string must start with {%% and end with %%}\"", [sname, where, v]),
	_pf_sfnql_fix, _pf_sfnql_url) if {
	some [name, p, sname, where, v] in _pf_sfnql_str
	startswith(v, "{%")
	not endswith(v, "%}")
}
