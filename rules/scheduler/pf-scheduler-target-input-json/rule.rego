package cdk_preflight

import rego.v1

# "JSON syntax error in input for the target" — a templated target's Input is
# passed through verbatim and must parse. Measured 2026-09-07,
# scheduler:CreateSchedule, us-east-1.
violation contains make_diag_full("pf-scheduler-target-input-json", "ERROR", name,
	"Properties.Target.Input",
	"Target Input is not valid JSON; CreateSchedule fails with \"JSON syntax error in input for the target\"",
	"Write Input as a JSON value",
	"https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-targets-templated.html") if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	inp := resolve(name, "Properties.Target.Input")
	is_string(inp)
	not json.is_valid(inp)
}
