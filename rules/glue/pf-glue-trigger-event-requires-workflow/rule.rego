package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-glue-trigger-event-requires-workflow", "ERROR", name,
	"Properties.WorkflowName",
	"An EVENT trigger has no WorkflowName; CreateTrigger fails with \"Workflow name cannot be null or empty\"",
	"Set WorkflowName to the AWS::Glue::Workflow this EventBridge trigger belongs to",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateTrigger.html") if {
	some name in resources_of_type("AWS::Glue::Trigger")
	_pf_gluelib_trigger_type(name) == "EVENT"
	_pf_gluelib_absent(name, "WorkflowName")
}
