package cdk_preflight

import rego.v1

# Same rule the scheduled triggers follow: both fields concrete and both "?"
# are refused. Only six-field cron() expressions are judged.
violation contains make_diag_full("pf-glue-crawler-schedule-day-of-month-or-week", "ERROR", name,
	"Properties.Schedule.ScheduleExpression",
	sprintf("Schedule '%s' sets day-of-month '%s' and day-of-week '%s'; exactly one of them has to be \"?\" and CreateCrawler fails with \"Invalid schedule cron expression: %s\"", [sch, f[2], f[4], sch]),
	"Put ? in whichever of day-of-month and day-of-week you are not constraining, e.g. cron(0 10 1 * ? *)",
	"https://docs.aws.amazon.com/glue/latest/dg/monitor-data-warehouse-schedule.html") if {
	some name in resources_of_type("AWS::Glue::Crawler")
	sch := _pf_gluelib_schedule_expression(name)
	f := _pf_gluelib_cron_fields(sch)
	count(f) == 6
	_pf_gluelib_cron_dom_dow_bad(f[2], f[4])
}
