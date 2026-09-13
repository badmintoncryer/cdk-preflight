package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-glue-trigger-conditional-requires-predicate", "ERROR", name,
	"Properties.Predicate",
	"A CONDITIONAL trigger has no Predicate; CreateTrigger fails with \"Predicate cannot be null or empty\"",
	"Add Predicate.Conditions naming the job or crawler state this trigger waits for",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateTrigger.html") if {
	some name in resources_of_type("AWS::Glue::Trigger")
	_pf_gluelib_trigger_type(name) == "CONDITIONAL"
	_pf_gluelib_absent(name, "Predicate")
}
