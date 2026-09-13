package cdk_preflight

import rego.v1

# Glue takes cron() in any case (Cron, CRON) but nothing else: rate() and bare
# prose are both refused. Leading whitespace is refused too, so the prefix test
# is the whole check.
violation contains make_diag_full("pf-glue-crawler-schedule-cron-only", "ERROR", name,
	"Properties.Schedule.ScheduleExpression",
	sprintf("The schedule expression \"%s\" is not a cron() expression; CreateCrawler fails with \"Invalid schedule cron expression. Expected format: Cron(CRON_EXPRESSION)\"", [expr]),
	"Write the schedule as cron(Minutes Hours Day-of-month Month Day-of-week Year); rate() is not supported for crawlers",
	"https://docs.aws.amazon.com/glue/latest/dg/monitor-data-warehouse-schedule.html") if {
	some name in resources_of_type("AWS::Glue::Crawler")
	expr := _pf_gluelib_schedule_expression(name)
	low := lower(expr)
	not startswith(low, "cron(")
}
