package cdk_preflight

import rego.v1

# Matcher objects inside an event pattern must name a real operator and give
# it a value of the right shape. Every case below was measured 2026-09-07 via
# events:PutRule in us-east-1, together with controls that must stay silent
# (cidr, equals-ignore-case, anything-but as a string / array / wildcard
# object, prefix and suffix taking {"equals-ignore-case": ...}, numeric with
# two bounds). Helpers live in rules/_lib/events.rego.
_pf_evpop_url := "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns-content-based-filtering.html"

_pf_evpop_operators := {
	"prefix", "suffix", "anything-but", "numeric", "exists",
	"cidr", "wildcard", "equals-ignore-case",
}

_pf_evpop_numeric_ops := {"<", "<=", "=", ">=", ">"}

# anything-but takes a scalar, an array, or an object using one of these.
_pf_evpop_anything_but_inner := {"prefix", "suffix", "wildcard", "equals-ignore-case"}

_pf_evpop_matchers(name) := _pf_evlib_matchers(_pf_evlib_pattern(name, "Properties.EventPattern"))

violation contains make_diag_full("pf-events-pattern-operator", "ERROR", name,
	"Properties.EventPattern",
	sprintf("'%s' is not an event-pattern operator; PutRule fails with \"Event pattern is not valid. Reason: Unrecognized match type %s\"", [k, k]),
	"Use one of prefix, suffix, anything-but, numeric, exists, cidr, wildcard, equals-ignore-case",
	_pf_evpop_url) if {
	some rt in ["AWS::Events::Rule", "AWS::Events::Archive"]
	some name in resources_of_type(rt)
	some m in _pf_evpop_matchers(name)
	some k, v in m
	not k in _pf_evpop_operators
}

violation contains make_diag_full("pf-events-pattern-operator", "ERROR", name,
	"Properties.EventPattern",
	sprintf("'%s' is not a numeric range operator; PutRule fails with \"Event pattern is not valid. Reason: Unrecognized numeric range operator: %s\"", [op, op]),
	"Use <, <=, =, >= or >",
	_pf_evpop_url) if {
	some rt in ["AWS::Events::Rule", "AWS::Events::Archive"]
	some name in resources_of_type(rt)
	some m in _pf_evpop_matchers(name)
	some i, op in object.get(m, "numeric", [])
	is_string(op)
	not op in _pf_evpop_numeric_ops
}

violation contains make_diag_full("pf-events-pattern-operator", "ERROR", name,
	"Properties.EventPattern",
	sprintf("anything-but cannot wrap '%s'; PutRule fails with \"Event pattern is not valid. Reason: Unsupported anything-but pattern: %s\"", [k, k]),
	"Give anything-but a scalar, an array, or an object using prefix, suffix, wildcard or equals-ignore-case",
	_pf_evpop_url) if {
	some rt in ["AWS::Events::Rule", "AWS::Events::Archive"]
	some name in resources_of_type(rt)
	some m in _pf_evpop_matchers(name)
	ab := object.get(m, "anything-but", null)
	is_object(ab)
	some k, v in ab
	not k in _pf_evpop_anything_but_inner
}

violation contains make_diag_full("pf-events-pattern-operator", "ERROR", name,
	"Properties.EventPattern",
	sprintf("%s takes a string or an {\"equals-ignore-case\": ...} object; PutRule fails with \"Event pattern is not valid. Reason: %s match pattern must be a string\"", [k, k]),
	sprintf("Give %s a string value", [k]),
	_pf_evpop_url) if {
	some rt in ["AWS::Events::Rule", "AWS::Events::Archive"]
	some name in resources_of_type(rt)
	some m in _pf_evpop_matchers(name)
	some k in ["prefix", "suffix"]
	v := object.get(m, k, "__pf_absent")
	v != "__pf_absent"
	not is_string(v)
	not is_object(v)
}

violation contains make_diag_full("pf-events-pattern-operator", "ERROR", name,
	"Properties.EventPattern",
	"exists takes a boolean; PutRule fails with \"Event pattern is not valid. Reason: exists match pattern must be either true or false.\"",
	"Write \"exists\": true or \"exists\": false, unquoted",
	_pf_evpop_url) if {
	some rt in ["AWS::Events::Rule", "AWS::Events::Archive"]
	some name in resources_of_type(rt)
	some m in _pf_evpop_matchers(name)
	v := object.get(m, "exists", "__pf_absent")
	v != "__pf_absent"
	not is_boolean(v)
}

violation contains make_diag_full("pf-events-pattern-operator", "ERROR", name,
	"Properties.EventPattern",
	sprintf("'%s' repeats the wildcard character; PutRule fails with \"Event pattern is not valid. Reason: Consecutive wildcard characters\"", [w]),
	"Use a single * between literal segments",
	_pf_evpop_url) if {
	some rt in ["AWS::Events::Rule", "AWS::Events::Archive"]
	some name in resources_of_type(rt)
	some m in _pf_evpop_matchers(name)
	w := object.get(m, "wildcard", null)
	is_string(w)
	contains(w, "**")
}
