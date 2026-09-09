package cdk_preflight

import rego.v1

_pf_asgscfw_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScheduledUpdateGroupAction.html"

violation contains make_diag_full("pf-asg-sched-recurrence-five-fields-no-cron-wrapper", "ERROR", name,
	"Properties.Recurrence",
	sprintf("Recurrence '%s' uses the cron(...) wrapper; Auto Scaling takes a bare Unix cron string and the create fails with \"Given recurrence string: %s is invalid\"", [v, v]),
	"Drop the cron(...) wrapper and pass the five fields on their own", _pf_asgscfw_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScheduledAction")
	v := resolve(name, "Properties.Recurrence")
	_pf_aslib_lit(v)
	startswith(v, "cron(")
}

violation contains make_diag_full("pf-asg-sched-recurrence-five-fields-no-cron-wrapper", "ERROR", name,
	"Properties.Recurrence",
	sprintf("Recurrence '%s' has %d fields; Auto Scaling takes exactly five (minute hour day-of-month month day-of-week) and the create fails with \"Given recurrence string: %s is invalid\"", [v, count(f), v]),
	"Use exactly five cron fields; there is no seconds field", _pf_asgscfw_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScheduledAction")
	v := resolve(name, "Properties.Recurrence")
	f := _pf_aslib_cron_fields(v)
	count(f) != 5
}
