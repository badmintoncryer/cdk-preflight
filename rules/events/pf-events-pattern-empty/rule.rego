package cdk_preflight

import rego.v1

# The engine's F3058 fires when the EventPattern KEY is absent, but an empty
# object passes the schema and the handler then treats it as no pattern at
# all. Fires only when ScheduleExpression is also literally absent — the
# bench-verified shape (absence proven via input.resources, see AGENTS.md).
violation contains make_diag_full("pf-events-pattern-empty", "ERROR", name,
	"Properties.EventPattern",
	"EventPattern is an empty object, which the handler treats as no pattern; PutRule fails with \"Parameter(s) EventPattern or ScheduleExpression must be specified\"",
	"Give EventPattern at least one matcher (e.g. source), or use ScheduleExpression instead",
	"https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html") if {
	some name in resources_of_type("AWS::Events::Rule")
	ep := resolve(name, "Properties.EventPattern")
	is_object(ep)
	count(ep) == 0
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "ScheduleExpression", "__pf_absent") == "__pf_absent"
}
