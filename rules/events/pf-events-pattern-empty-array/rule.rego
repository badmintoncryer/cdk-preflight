package cdk_preflight

import rego.v1

# "Event pattern is not valid. Reason: Empty arrays are not allowed" — an
# empty matcher list matches nothing and PutRule refuses it, at the top level
# and nested alike. Measured 2026-09-07, events:PutRule, us-east-1.
violation contains make_diag_full("pf-events-pattern-empty-array", "ERROR", name,
	"Properties.EventPattern",
	"An event pattern holds an empty array; PutRule fails with \"Event pattern is not valid. Reason: Empty arrays are not allowed\"",
	"Give the key at least one value, or drop the key",
	"https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html") if {
	some rt in ["AWS::Events::Rule", "AWS::Events::Archive"]
	some name in resources_of_type(rt)
	some a in _pf_evlib_arrays(_pf_evlib_pattern(name, "Properties.EventPattern"))
	count(a) == 0
}
