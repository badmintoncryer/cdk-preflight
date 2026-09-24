package cdk_preflight

import rego.v1

# "Schedule expressions must have the following syntax: rate(<number>\s?(minutes?
# |hours?|days?)), cron(<cron_expression>) or at(yyyy-MM-dd'T'HH:mm:ss)". A bare
# cron body with no cron() wrapper is the common mistake. The keyword match is
# case-insensitive on purpose: only a shape that is certainly rejected fires.
violation contains make_diag_full("pf-appautoscaling-schedule-expression-form", "ERROR", name,
	sprintf("Properties.ScheduledActions.%d.Schedule", [item.index]),
	sprintf("Schedule '%s' is none of at(), rate() or cron(); PutScheduledAction fails with \"Invalid schedule expression\"", [s]),
	"Wrap the expression: cron(0 8 1 * ? *), rate(5 minutes) or at(2035-01-01T00:00:00)",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PutScheduledAction.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	some item in flatten_list(name, "Properties.ScheduledActions")
	sched := item.value
	is_object(sched)
	s := object.get(sched, "Schedule", null)
	is_string(s)
	not regex.match(`(?i)^(at|rate|cron)\(.*\)$`, s)
}
