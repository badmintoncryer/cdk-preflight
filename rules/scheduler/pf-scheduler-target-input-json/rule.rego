package cdk_preflight

import rego.v1

# "JSON syntax error in input for the target" — a templated target's Input is
# passed through verbatim and must parse. Measured 2026-09-07,
# scheduler:CreateSchedule, us-east-1.
_pf_sti_text_target(name) if {
	t := resolve(name, "Properties.Target.Arn")
	some type in ["AWS::SQS::Queue", "AWS::SNS::Topic"]
	t in resources_of_type(type)
}

_pf_sti_text_target(name) if {
	t := resolve(name, "Properties.Target.Arn")
	is_string(t)
	not input.resources[t]
	regex.match(`^arn:[^:]+:(sqs|sns):`, t)
}

violation contains make_diag_full("pf-scheduler-target-input-json", "ERROR", name,
	"Properties.Target.Input",
	"Target Input is not valid JSON; CreateSchedule fails with \"JSON syntax error in input for the target\"",
	"Write Input as a JSON value",
	"https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-targets-templated.html") if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	inp := resolve(name, "Properties.Target.Input")
	is_string(inp)
	not input.resources[inp]
	not json.is_valid(inp)
	# an SQS or SNS target takes the Input as the message body, so any text deploys
	# (aws-cdk integ.schedule-with-dlq: "testing dlq" to a queue)
	not _pf_sti_text_target(name)
}
