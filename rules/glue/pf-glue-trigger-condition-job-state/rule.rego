package cdk_preflight

import rego.v1

_pf_gluetjs_states := {"SUCCEEDED", "STOPPED", "FAILED", "TIMEOUT"}

violation contains make_diag_full("pf-glue-trigger-condition-job-state", "ERROR", name,
	sprintf("Properties.Predicate.Conditions.%d.State", [i]),
	sprintf("Condition State '%v' is not a job run state a trigger can watch; CreateTrigger fails with \"JobRunState should be any of: [SUCCEEDED, STOPPED, FAILED, TIMEOUT]\"", [s]),
	"Use SUCCEEDED, STOPPED, FAILED or TIMEOUT",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateTrigger.html") if {
	some name in resources_of_type("AWS::Glue::Trigger")
	some i, c in _pf_gluelib_conditions(name)
	is_object(c)
	s := object.get(c, "State", null)
	_pf_gluelib_lit(s)
	not s in _pf_gluetjs_states
}
