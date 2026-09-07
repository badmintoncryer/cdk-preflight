package cdk_preflight

import rego.v1

_pf_evpsv_scalar(v) if is_string(v)

_pf_evpsv_scalar(v) if is_number(v)

_pf_evpsv_scalar(v) if is_boolean(v)

# Every matcher in an event pattern must be an array (or an object holding
# operators); a bare scalar is rejected per key, at any depth
# ({"detail": {"a": {"b": {"c": "plain"}}}} gives the same message —
# measured 2026-09-07 via events:PutRule). AWS::Events::Archive runs the same
# validator. The node walk in rules/_lib/events.rego only descends through
# object *values* and $or branches, so matcher objects like {"prefix": "..."}
# — which are array elements and legally carry scalars — are never visited.
violation contains make_diag_full("pf-events-pattern-scalar-value", "ERROR", name,
	sprintf("Properties.EventPattern.%s", [k]),
	sprintf("EventPattern key '%s' holds a bare scalar; PutRule rejects it with \"Event pattern is not valid. Reason: \\\"%s\\\" must be an object or an array\"", [k, k]),
	sprintf("Wrap the value in an array: \"%s\": [...]", [k]),
	"https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html") if {
	some rt in ["AWS::Events::Rule", "AWS::Events::Archive"]
	some name in resources_of_type(rt)
	some n in _pf_evlib_nodes(_pf_evlib_pattern(name, "Properties.EventPattern"))
	some k, v in n
	_pf_evpsv_scalar(v)
}
