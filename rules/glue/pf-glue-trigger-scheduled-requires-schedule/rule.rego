package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-glue-trigger-scheduled-requires-schedule", "ERROR", name,
	"Properties.Schedule",
	"A SCHEDULED trigger has no Schedule; CreateTrigger fails with \"Schedule cannot be null or empty\"",
	"Set Schedule to a six-field cron() expression, e.g. cron(0 10 1 * ? *)",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateTrigger.html") if {
	some name in resources_of_type("AWS::Glue::Trigger")
	_pf_gluelib_trigger_type(name) == "SCHEDULED"
	_pf_gluelib_absent(name, "Schedule")
}
