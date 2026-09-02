package cdk_preflight

import rego.v1

_pf_evpsv_scalar(v) if is_string(v)

_pf_evpsv_scalar(v) if is_number(v)

_pf_evpsv_scalar(v) if is_boolean(v)

# Every matcher in an event pattern must be an array (or an object holding
# operators); a bare scalar is rejected per key. Only the top level is
# checked — that is the bench-verified scope, and it dodges operator objects
# like {"prefix": "..."} that legally carry scalars deeper down.
violation contains make_diag_full("pf-events-pattern-scalar-value", "ERROR", name,
	sprintf("Properties.EventPattern.%s", [k]),
	sprintf("EventPattern key '%s' holds a bare scalar; PutRule rejects it with \"Event pattern is not valid. Reason: \\\"%s\\\" must be an object or an array\"", [k, k]),
	sprintf("Wrap the value in an array: \"%s\": [...]", [k]),
	"https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html") if {
	some name in resources_of_type("AWS::Events::Rule")
	ep := resolve(name, "Properties.EventPattern")
	is_object(ep)
	some k, v in ep
	_pf_evpsv_scalar(v)
}
