package cdk_preflight

import rego.v1

# PutScheduledAction validates ScheduledActionName before it looks the scalable
# target up, so a bad name fails the stack even when everything else is right.
# The published pattern is built out of negative lookaheads, which this engine's
# regex flavour cannot compile at all, so the three forbidden shapes are matched
# positively instead.
_pf_aassan_bad(n) if regex.match(`[\x00-\x1f\x7f-\x9f:/|]`, n)

_pf_aassan_bad(n) if startswith(n, " ")

_pf_aassan_bad(n) if endswith(n, " ")

violation contains make_diag_full("pf-appautoscaling-scheduled-action-name-chars", "ERROR", name,
	sprintf("Properties.ScheduledActions.%d.ScheduledActionName", [item.index]),
	sprintf("ScheduledActionName '%s' uses a character PutScheduledAction refuses: ':', '/', '|', a control character, or a leading/trailing space", [n]),
	"Rename the scheduled action using letters, digits, '-' and '_'",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PutScheduledAction.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	some item in flatten_list(name, "Properties.ScheduledActions")
	sched := item.value
	is_object(sched)
	n := object.get(sched, "ScheduledActionName", null)
	is_string(n)
	_pf_aassan_bad(n)
}
