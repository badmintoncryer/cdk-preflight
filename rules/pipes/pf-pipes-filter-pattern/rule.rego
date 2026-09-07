package cdk_preflight

import rego.v1

# A pipe filter Pattern is an event pattern carried as a JSON string, and
# CreatePipe runs the same validator EventBridge uses: it must parse, it must
# not be an empty object, and a matcher may not be a bare scalar. Measured
# 2026-09-07, pipes:CreatePipe, us-east-1. Rego has no walk builtin and no
# recursion, so the scalar check is unrolled to three levels — enough for the
# envelope-then-payload shape a pipe pattern actually has. Operator objects
# ({"prefix": "..."}) sit inside arrays, so they are never reached.
_pf_pipefp_url := "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html"

_pf_pipefp_scalar(v) if is_string(v)

_pf_pipefp_scalar(v) if is_number(v)

_pf_pipefp_scalar(v) if is_boolean(v)

# The engine's Rego dialect allows only one `some ... in` per comprehension
# body, so each level gets its own helper and the levels are unioned. Three
# levels cover the envelope-then-payload shape a pipe pattern actually has.
_pf_pipefp_kids(obj) := {v | some k, v in obj; is_object(v)}

_pf_pipefp_scalar_keys(obj) := {k | some k, v in obj; _pf_pipefp_scalar(v)}

_pf_pipefp_grandkids(obj) := union({_pf_pipefp_kids(kid) | some kid in _pf_pipefp_kids(obj)})

_pf_pipefp_bad_keys(obj) := union({
	_pf_pipefp_scalar_keys(obj),
	union({_pf_pipefp_scalar_keys(d1) | some d1 in _pf_pipefp_kids(obj)}),
	union({_pf_pipefp_scalar_keys(d2) | some d2 in _pf_pipefp_grandkids(obj)}),
})

_pf_pipefp_patterns(name) := [f |
	some f in flatten_list(name, "Properties.SourceParameters.FilterCriteria.Filters")
	is_object(f.value)
	is_string(object.get(f.value, "Pattern", null))
]

violation contains make_diag_full("pf-pipes-filter-pattern", "ERROR", name,
	sprintf("Properties.SourceParameters.FilterCriteria.Filters.%d.Pattern", [f.index]),
	"The filter Pattern is not valid JSON; CreatePipe fails with \"Invalid Event Pattern\"",
	"Write the Pattern as a JSON object serialised to a string",
	_pf_pipefp_url) if {
	some name in resources_of_type("AWS::Pipes::Pipe")
	some f in _pf_pipefp_patterns(name)
	not json.is_valid(object.get(f.value, "Pattern", ""))
}

violation contains make_diag_full("pf-pipes-filter-pattern", "ERROR", name,
	sprintf("Properties.SourceParameters.FilterCriteria.Filters.%d.Pattern", [f.index]),
	"The filter Pattern is an empty object; CreatePipe fails with \"Invalid Event Pattern. Reason: Empty objects are not allowed\"",
	"Give the pattern at least one matcher, or drop FilterCriteria",
	_pf_pipefp_url) if {
	some name in resources_of_type("AWS::Pipes::Pipe")
	some f in _pf_pipefp_patterns(name)
	raw := object.get(f.value, "Pattern", "")
	json.is_valid(raw)
	obj := json.unmarshal(raw)
	is_object(obj)
	count(obj) == 0
}

violation contains make_diag_full("pf-pipes-filter-pattern", "ERROR", name,
	sprintf("Properties.SourceParameters.FilterCriteria.Filters.%d.Pattern", [f.index]),
	sprintf("Pattern key '%s' holds a bare scalar; CreatePipe fails with \"Invalid Event Pattern. Reason: \\\"%s\\\" must be an object or an array\"", [k, k]),
	sprintf("Wrap the value in an array: \"%s\": [...]", [k]),
	_pf_pipefp_url) if {
	some name in resources_of_type("AWS::Pipes::Pipe")
	some f in _pf_pipefp_patterns(name)
	raw := object.get(f.value, "Pattern", "")
	json.is_valid(raw)
	obj := json.unmarshal(raw)
	is_object(obj)
	some k in _pf_pipefp_bad_keys(obj)
}
