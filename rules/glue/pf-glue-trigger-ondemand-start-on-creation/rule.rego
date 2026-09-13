package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-glue-trigger-ondemand-start-on-creation", "ERROR", name,
	"Properties.StartOnCreation",
	"StartOnCreation is true on an ON_DEMAND trigger; CreateTrigger fails with \"Starting trigger on create is not supported for ON_DEMAND trigger type.\"",
	"Drop StartOnCreation (or set it to false); only SCHEDULED and CONDITIONAL triggers can start on creation",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateTrigger.html") if {
	some name in resources_of_type("AWS::Glue::Trigger")
	_pf_gluelib_trigger_type(name) == "ON_DEMAND"
	_pf_gluelib_get(name, "StartOnCreation") in {true, "true"}
}
