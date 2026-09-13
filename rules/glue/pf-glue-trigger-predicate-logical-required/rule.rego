package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-glue-trigger-predicate-logical-required", "ERROR", name,
	"Properties.Predicate.Logical",
	sprintf("Predicate lists %d conditions but has no Logical; CreateTrigger fails with \"Logical operator cannot be null or empty when more than one condition is present.\"", [count(conds)]),
	"Set Predicate.Logical to AND or ANY",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateTrigger.html") if {
	some name in resources_of_type("AWS::Glue::Trigger")
	p := _pf_gluelib_predicate(name)
	conds := _pf_gluelib_conditions(name)
	count(conds) > 1
	object.get(p, "Logical", "__pf_absent") == "__pf_absent"
}
