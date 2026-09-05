package cdk_preflight

import rego.v1

_pf_sfnjp_url := "https://docs.aws.amazon.com/step-functions/latest/dg/input-output-paths.html"

_pf_sfnjp_fix := "Write paths as $.field (Reference Paths for ResultPath/ItemsPath), \".$\" values as $.path or States.Func(...), and variable names as letters/digits"

_pf_sfnjp_pathfields := {"InputPath", "OutputPath", "ResultPath", "ItemsPath", "TimeoutSecondsPath", "HeartbeatSecondsPath", "SecondsPath", "TimestampPath", "MaxConcurrencyPath", "ToleratedFailurePercentagePath", "ToleratedFailureCountPath", "ErrorPath", "CausePath"}

violation contains make_diag_full("pf-sfn-asl-jsonpath-syntax", "ERROR", name,
	sprintf("%s.%s", [_pf_sfnlib_path(name, p, sname), f]),
	sprintf("state '%s' %s '%s' is not a JSONPath (must start with $); CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Value must be a valid JSONPath.\"", [sname, f, v]),
	_pf_sfnjp_fix, _pf_sfnjp_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some f in _pf_sfnjp_pathfields
	v := object.get(st, f, null)
	is_string(v)
	not startswith(v, "$")
	not contains(v, "${")
}

violation contains make_diag_full("pf-sfn-asl-jsonpath-syntax", "ERROR", name,
	sprintf("%s.Choices[%d].%s", [_pf_sfnlib_path(name, p, sname), i, k]),
	sprintf("Choice state '%s' rule %d %s '%s' is not a Reference Path (must start with $); CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Value is not a Reference Path: Reference path didn't start with '$'\"", [sname, i, k, v]),
	_pf_sfnjp_fix, _pf_sfnjp_url) if {
	some [name, p, s, sname, i, c] in _pf_sfnlib_choice
	some k, v in c
	is_string(v)
	k in {"Variable", "StringEqualsPath", "StringLessThanPath", "StringGreaterThanPath", "StringLessThanEqualsPath", "StringGreaterThanEqualsPath", "NumericEqualsPath", "NumericLessThanPath", "NumericGreaterThanPath", "NumericLessThanEqualsPath", "NumericGreaterThanEqualsPath", "BooleanEqualsPath", "TimestampEqualsPath", "TimestampLessThanPath", "TimestampGreaterThanPath", "TimestampLessThanEqualsPath", "TimestampGreaterThanEqualsPath"}
	not startswith(v, "$")
}

_pf_sfnjp_refpath contains [name, path, v] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some f in ["ResultPath", "ItemsPath"]
	v := object.get(st, f, null)
	is_string(v)
	path := sprintf("%s.%s", [_pf_sfnlib_path(name, p, sname), f])
}

_pf_sfnjp_refpath contains [name, path, v] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	arr := object.get(st, "Catch", [])
	is_array(arr)
	some i, c in arr
	is_object(c)
	v := object.get(c, "ResultPath", null)
	is_string(v)
	path := sprintf("%s.Catch[%d].ResultPath", [_pf_sfnlib_path(name, p, sname), i])
}

violation contains make_diag_full("pf-sfn-asl-jsonpath-syntax", "ERROR", name,
	path,
	sprintf("'%s' is not a Reference Path: wildcards, filters and deep scans (* .. ? @) are not allowed where a single JSON node is addressed; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Value is not a Reference Path\"", [v]),
	_pf_sfnjp_fix, _pf_sfnjp_url) if {
	some [name, path, v] in _pf_sfnjp_refpath
	regex.match("[*?@]|[.][.]", v)
}

# ".$" keys of payload templates (Parameters / ResultSelector / ItemSelector),
# two levels deep.
_pf_sfnjp_dollar contains [name, path, v] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some f in ["Parameters", "ResultSelector", "ItemSelector"]
	o := object.get(st, f, null)
	is_object(o)
	some k, v in o
	endswith(k, ".$")
	is_string(v)
	path := sprintf("%s.%s.%s", [_pf_sfnlib_path(name, p, sname), f, k])
}

_pf_sfnjp_dollar contains [name, path, v] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some f in ["Parameters", "ResultSelector", "ItemSelector"]
	o := object.get(st, f, null)
	is_object(o)
	some k, o2 in o
	is_object(o2)
	some k2, v in o2
	endswith(k2, ".$")
	is_string(v)
	path := sprintf("%s.%s.%s.%s", [_pf_sfnlib_path(name, p, sname), f, k, k2])
}

violation contains make_diag_full("pf-sfn-asl-jsonpath-syntax", "ERROR", name,
	path,
	sprintf("value '%s' of a \".$\" key must be a JSONPath ($...) or an intrinsic function (States....); CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: The value for the field '...$' must be a valid JSONPath or a valid intrinsic function call\"", [v]),
	_pf_sfnjp_fix, _pf_sfnjp_url) if {
	some [name, path, v] in _pf_sfnjp_dollar
	not startswith(v, "$")
	not startswith(v, "States.")
	not contains(v, "${")
}

violation contains make_diag_full("pf-sfn-asl-jsonpath-syntax", "ERROR", name,
	sprintf("%s.Assign.%s", [_pf_sfnlib_path(name, p, sname), k]),
	sprintf("state '%s' assigns the reserved variable name 'states'; CreateStateMachine fails with \"RESERVED_VARIABLE_NAME: Cannot assign to reserved variable '$states'.\"", [sname]),
	_pf_sfnjp_fix, _pf_sfnjp_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	a := object.get(st, "Assign", null)
	is_object(a)
	some k, _ in a
	k == "states"
}

violation contains make_diag_full("pf-sfn-asl-jsonpath-syntax", "ERROR", name,
	sprintf("%s.Assign.%s", [_pf_sfnlib_path(name, p, sname), k]),
	sprintf("state '%s' assigns variable '%s'; variable names are letters and digits starting with a letter, and CreateStateMachine fails with \"INVALID_VARIABLE_NAME: Invalid variable name '%s': the variable name contains invalid characters.\"", [sname, k, k]),
	_pf_sfnjp_fix, _pf_sfnjp_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	a := object.get(st, "Assign", null)
	is_object(a)
	some k, _ in a
	not regex.match("^[A-Za-z][A-Za-z0-9_]*$", k)
}
