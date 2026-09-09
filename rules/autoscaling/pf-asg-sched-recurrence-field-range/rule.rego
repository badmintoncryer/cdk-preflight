package cdk_preflight

import rego.v1

_pf_asgscfr_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScheduledUpdateGroupAction.html"

_pf_asgscfr_lo := [0, 0, 1, 1, 0]

_pf_asgscfr_hi := [59, 23, 31, 12, 7]

_pf_asgscfr_field := ["minute", "hour", "day-of-month", "month", "day-of-week"]

_pf_asgscfr_out(i, n) if n < _pf_asgscfr_lo[i]

_pf_asgscfr_out(i, n) if n > _pf_asgscfr_hi[i]

violation contains make_diag_full("pf-asg-sched-recurrence-field-range", "ERROR", name,
	"Properties.Recurrence",
	sprintf("Recurrence '%s' puts %d in the %s field, which runs %d-%d; the create fails with \"Given recurrence string: %s is invalid\"", [v, n, _pf_asgscfr_field[i], _pf_asgscfr_lo[i], _pf_asgscfr_hi[i], v]),
	"Bring every cron field into its own range", _pf_asgscfr_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScheduledAction")
	v := resolve(name, "Properties.Recurrence")
	f := _pf_aslib_cron_fields(v)
	count(f) == 5
	some i, field in f
	some n in _pf_aslib_cron_nums(field)
	_pf_asgscfr_out(i, n)
}
