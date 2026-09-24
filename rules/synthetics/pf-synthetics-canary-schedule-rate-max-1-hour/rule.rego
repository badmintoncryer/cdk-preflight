package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-synthetics-canary-schedule-rate-max-1-hour", "ERROR", name,
	"Properties.Schedule.Expression",
	sprintf("Schedule.Expression '%s' runs the canary every %v minutes; a rate() interval cannot exceed one hour and CreateCanary answers \"Invalid Schedule Expression.\"", [expr, mins]),
	"Use rate(60 minutes) or less — rate(0 minute) runs the canary exactly once — or switch to a cron() expression",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-synthetics-canary-schedule.html") if {
	some name in resources_of_type("AWS::Synthetics::Canary")
	expr := resolve(name, "Properties.Schedule.Expression")
	r := _pf_synlib_rate(expr)
	mins := _pf_synlib_rate_minutes(r[0], r[1])
	mins > 60
}
