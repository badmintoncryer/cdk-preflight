package cdk_preflight

import rego.v1

_pf_sfnch_url := "https://docs.aws.amazon.com/step-functions/latest/dg/state-choice.html"

_pf_sfnch_fix := "Give every top-level Choice rule one comparison (or one And/Or/Not/Condition) and a Next; nested rules carry no Next"

_pf_sfnch_cmp := {"StringEquals", "StringEqualsPath", "StringLessThan", "StringLessThanPath", "StringGreaterThan", "StringGreaterThanPath", "StringLessThanEquals", "StringLessThanEqualsPath", "StringGreaterThanEquals", "StringGreaterThanEqualsPath", "StringMatches", "NumericEquals", "NumericEqualsPath", "NumericLessThan", "NumericLessThanPath", "NumericGreaterThan", "NumericGreaterThanPath", "NumericLessThanEquals", "NumericLessThanEqualsPath", "NumericGreaterThanEquals", "NumericGreaterThanEqualsPath", "BooleanEquals", "BooleanEqualsPath", "TimestampEquals", "TimestampEqualsPath", "TimestampLessThan", "TimestampLessThanPath", "TimestampGreaterThan", "TimestampGreaterThanPath", "TimestampLessThanEquals", "TimestampLessThanEqualsPath", "TimestampGreaterThanEquals", "TimestampGreaterThanEqualsPath", "IsNull", "IsPresent", "IsNumeric", "IsString", "IsBoolean", "IsTimestamp"}

_pf_sfnch_sel := {"And", "Or", "Not", "Variable", "Condition"}

violation contains make_diag_full("pf-sfn-asl-choice-rules", "ERROR", name,
	sprintf("%s.Choices", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("Choice state '%s' has an empty Choices array; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Value cannot be empty\"", [sname]),
	_pf_sfnch_fix, _pf_sfnch_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	object.get(st, "Type", null) == "Choice"
	arr := object.get(st, "Choices", null)
	is_array(arr)
	count(arr) == 0
}

violation contains make_diag_full("pf-sfn-asl-choice-rules", "ERROR", name,
	sprintf("%s.Choices[%d]", [_pf_sfnlib_path(name, p, sname), i]),
	sprintf("Choice state '%s' rule %d has no Next; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: These fields are required: [Next]\"", [sname, i]),
	_pf_sfnch_fix, _pf_sfnch_url) if {
	some [name, p, s, sname, i, c] in _pf_sfnlib_choice
	not _pf_sfnlib_has(c, "Next")
}

violation contains make_diag_full("pf-sfn-asl-choice-rules", "ERROR", name,
	sprintf("%s.Choices[%d].%s", [_pf_sfnlib_path(name, p, sname), i, op]),
	sprintf("Choice state '%s' rule %d nests a Next inside %s; only the top-level rule may carry Next, and CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Field 'Next' is not supported\"", [sname, i, op]),
	_pf_sfnch_fix, _pf_sfnch_url) if {
	some [name, p, s, sname, i, c] in _pf_sfnlib_choice
	some op in ["And", "Or"]
	arr := object.get(c, op, [])
	is_array(arr)
	some sub in arr
	is_object(sub)
	_pf_sfnlib_has(sub, "Next")
}

violation contains make_diag_full("pf-sfn-asl-choice-rules", "ERROR", name,
	sprintf("%s.Choices[%d].Not", [_pf_sfnlib_path(name, p, sname), i]),
	sprintf("Choice state '%s' rule %d nests a Next inside Not; only the top-level rule may carry Next, and CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Field 'Next' is not supported\"", [sname, i]),
	_pf_sfnch_fix, _pf_sfnch_url) if {
	some [name, p, s, sname, i, c] in _pf_sfnlib_choice
	sub := object.get(c, "Not", null)
	is_object(sub)
	_pf_sfnlib_has(sub, "Next")
}

violation contains make_diag_full("pf-sfn-asl-choice-rules", "ERROR", name,
	sprintf("%s.Choices[%d]", [_pf_sfnlib_path(name, p, sname), i]),
	sprintf("Choice state '%s' rule %d has %d comparison operators; a Variable rule takes exactly one, and CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: There should only be one of the following fields: [StringEquals, ...]\"", [sname, i, n]),
	_pf_sfnch_fix, _pf_sfnch_url) if {
	some [name, p, s, sname, i, c] in _pf_sfnlib_choice
	_pf_sfnlib_has(c, "Variable")
	n := count({k | some k, _ in c; k in _pf_sfnch_cmp})
	n != 1
}

violation contains make_diag_full("pf-sfn-asl-choice-rules", "ERROR", name,
	sprintf("%s.Choices[%d]", [_pf_sfnlib_path(name, p, sname), i]),
	sprintf("Choice state '%s' rule %d must have exactly one of And / Or / Not / Variable / Condition (found %d); CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: The object must have only one of the following fields, [And, Or, Not, Variable, Condition]\"", [sname, i, n]),
	_pf_sfnch_fix, _pf_sfnch_url) if {
	some [name, p, s, sname, i, c] in _pf_sfnlib_choice
	n := count({k | some k, _ in c; k in _pf_sfnch_sel})
	n != 1
}
