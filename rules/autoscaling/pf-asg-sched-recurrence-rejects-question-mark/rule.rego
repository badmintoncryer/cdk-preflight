package cdk_preflight

import rego.v1

_pf_asgscqm_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScheduledUpdateGroupAction.html"

violation contains make_diag_full("pf-asg-sched-recurrence-rejects-question-mark", "ERROR", name,
	"Properties.Recurrence",
	sprintf("Recurrence '%s' uses the '?' wildcard; that is EventBridge cron syntax, and Auto Scaling's Unix cron rejects it with \"Given recurrence string: %s is invalid\"", [v, v]),
	"Use '*' instead of '?' in the day-of-month and day-of-week fields", _pf_asgscqm_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScheduledAction")
	v := resolve(name, "Properties.Recurrence")
	f := _pf_aslib_cron_fields(v)
	some field in f
	contains(field, "?")
}
