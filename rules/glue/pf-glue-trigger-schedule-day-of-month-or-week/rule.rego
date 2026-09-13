package cdk_preflight

import rego.v1

# Glue rejects both fields being concrete and both being "?": exactly one of the
# two has to be "?". Only six-field cron() expressions are judged; anything else
# is a different constraint and stays silent here. The parser lives in
# rules/_lib/glue.rego because the crawler schedules take the same check.
violation contains make_diag_full("pf-glue-trigger-schedule-day-of-month-or-week", "ERROR", name,
	"Properties.Schedule",
	sprintf("Schedule '%s' sets day-of-month '%s' and day-of-week '%s'; exactly one of them has to be \"?\" and CreateTrigger fails with \"The schedule %s is invalid.\"", [sch, f[2], f[4], sch]),
	"Put ? in whichever of day-of-month and day-of-week you are not constraining, e.g. cron(0 10 1 * ? *)",
	"https://docs.aws.amazon.com/glue/latest/dg/monitor-data-warehouse-schedule.html") if {
	some name in resources_of_type("AWS::Glue::Trigger")
	sch := _pf_gluelib_str(name, "Properties.Schedule")
	f := _pf_gluelib_cron_fields(sch)
	count(f) == 6
	_pf_gluelib_cron_dom_dow_bad(f[2], f[4])
}
