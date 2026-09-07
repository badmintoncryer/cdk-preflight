package cdk_preflight

import rego.v1

# $or replaces the object it sits in; giving it siblings makes EventBridge
# read the whole object as a matcher and fail with "Unrecognized match type
# <sibling>". Measured 2026-09-07, events:PutRule, us-east-1: $or alone (top
# level or nested) is accepted, $or beside another key is not.
violation contains make_diag_full("pf-events-pattern-or-exclusive", "ERROR", name,
	"Properties.EventPattern",
	sprintf("$or is used alongside %v; PutRule fails with \"Event pattern is not valid. Reason: Unrecognized match type <sibling key>\"", [sort(siblings)]),
	"Move the sibling keys into each $or branch",
	"https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns-or-matching.html") if {
	some rt in ["AWS::Events::Rule", "AWS::Events::Archive"]
	some name in resources_of_type(rt)
	some n in _pf_evlib_nodes(_pf_evlib_pattern(name, "Properties.EventPattern"))
	object.get(n, "$or", "__pf_absent") != "__pf_absent"
	siblings := {k | some k, v in n; k != "$or"}
	count(siblings) > 0
}
