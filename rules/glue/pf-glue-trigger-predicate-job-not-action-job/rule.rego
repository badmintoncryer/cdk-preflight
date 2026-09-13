package cdk_preflight

import rego.v1

# The job that fires the trigger cannot also be the job the trigger starts.
violation contains make_diag_full("pf-glue-trigger-predicate-job-not-action-job", "ERROR", name,
	"Properties.Actions",
	sprintf("Job %v is both a predicate condition and an action; CreateTrigger fails with \"Job cannot be a Predicate and Action for Conditional Trigger.\"", [j]),
	"Point the action at a different job, or watch a different job in the predicate",
	"https://docs.aws.amazon.com/glue/latest/dg/monitor-data-warehouse-schedule.html") if {
	some name in resources_of_type("AWS::Glue::Trigger")
	_pf_gluelib_trigger_type(name) == "CONDITIONAL"
	some c in _pf_gluelib_conditions(name)
	is_object(c)
	j := object.get(c, "JobName", null)
	j != null
	acts := _pf_gluelib_get(name, "Actions")
	is_array(acts)
	some a in acts
	is_object(a)
	object.get(a, "JobName", null) == j
}
