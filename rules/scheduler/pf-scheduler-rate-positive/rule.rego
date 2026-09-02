package cdk_preflight

import rego.v1

# The engine's E3027 validates rate() bounds for AWS::Events::Rule but not
# for AWS::Scheduler::Schedule — same constraint family, different resource.
# Only the value bound is checked here; unit spellings differ between the two
# services and were not measured for Scheduler.
violation contains make_diag_full("pf-scheduler-rate-positive", "ERROR", name,
	"Properties.ScheduleExpression",
	sprintf("The rate value in '%s' is not positive; CreateSchedule fails with \"Invalid Schedule Expression %s.\"", [expr, expr]),
	"Use a rate of 1 or more (e.g. rate(5 minutes))",
	"https://docs.aws.amazon.com/scheduler/latest/UserGuide/schedule-types.html") if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	expr := resolve(name, "Properties.ScheduleExpression")
	is_string(expr)
	t := trim_space(expr)
	startswith(t, "rate(")
	endswith(t, ")")
	inner := trim_space(substring(t, 5, count(t) - 6))
	parts := split(inner, " ")
	n := to_number(parts[0])
	n <= 0
}
