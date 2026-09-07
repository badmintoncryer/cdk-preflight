package cdk_preflight

import rego.v1

# A universal target is arn:aws:scheduler:::aws-sdk:<service>:<api>, needs an
# Input carrying the API request, and cannot call a read-only API. Measured
# 2026-09-07, scheduler:CreateSchedule, us-east-1: an ARN carrying a Region
# and account gives "scheduler is not a supported service for a target", a
# missing Input gives "You must provide an input to set this target for your
# schedule", and getQueueUrl / describeInstances / listQueues each give
# "<api> API is not supported" while sendMessage and startInstances deploy.
_pf_schuni_url := "https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-targets-universal.html"

_pf_schuni_arn(name) := a if {
	a := resolve(name, "Properties.Target.Arn")
	is_string(a)
	contains(a, ":aws-sdk:")
}

# arn:aws:scheduler:::aws-sdk:<service>:<api> — the API is the 8th segment.
_pf_schuni_api(a) := parts[7] if {
	parts := split(a, ":")
	count(parts) > 7
}

_pf_schuni_readonly_prefixes := ["get", "describe", "list"]

violation contains make_diag_full("pf-scheduler-universal-target", "ERROR", name,
	"Properties.Target.Arn",
	sprintf("'%s' carries a Region or account; a universal target ARN is arn:aws:scheduler:::aws-sdk:<service>:<api> with both empty, and CreateSchedule otherwise fails with \"scheduler is not a supported service for a target\"", [arn]),
	"Write the ARN as arn:aws:scheduler:::aws-sdk:<service>:<api>",
	_pf_schuni_url) if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	arn := _pf_schuni_arn(name)
	not startswith(arn, "arn:aws:scheduler:::aws-sdk:")
}

violation contains make_diag_full("pf-scheduler-universal-target", "ERROR", name,
	"Properties.Target.Input",
	"A universal target carries the API request in Input; CreateSchedule fails with \"You must provide an input to set this target for your schedule\"",
	"Set Target.Input to the JSON request for the API",
	_pf_schuni_url) if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	_pf_schuni_arn(name)
	object.get(input.resources[name].properties.Target, "Input", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-scheduler-universal-target", "ERROR", name,
	"Properties.Target.Arn",
	sprintf("'%s' is a read-only API, which a schedule cannot call; CreateSchedule fails with \"%s API is not supported\"", [api, api]),
	"Target an API that changes state",
	_pf_schuni_url) if {
	some name in resources_of_type("AWS::Scheduler::Schedule")
	arn := _pf_schuni_arn(name)
	api := _pf_schuni_api(arn)
	some p in _pf_schuni_readonly_prefixes
	startswith(api, p)
}
