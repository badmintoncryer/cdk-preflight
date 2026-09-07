package cdk_preflight

import rego.v1

# "The StartDate you specify must come before the EndDate." Measured
# 2026-09-07, scheduler:CreateSchedule, us-east-1. ISO 8601 timestamps in the
# same shape compare correctly as strings, so the check needs no date parsing;
# mixed shapes simply do not match the pattern and are skipped.
_pf_schse_iso(v) if regex.match(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z?$`, v)

violation contains make_diag_full("pf-scheduler-start-end-order", "ERROR", name,
	"Properties.EndDate",
	sprintf("StartDate %s is not before EndDate %s; CreateSchedule fails with \"The StartDate you specify must come before the EndDate\"", [s, e]),
	"Set EndDate after StartDate",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-scheduler-schedule.html") if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	s := resolve(name, "Properties.StartDate")
	e := resolve(name, "Properties.EndDate")
	is_string(s)
	is_string(e)
	_pf_schse_iso(s)
	_pf_schse_iso(e)
	s >= e
}
