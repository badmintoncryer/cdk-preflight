package cdk_preflight

import rego.v1

_pf_gluetcs_states := {"SUCCEEDED", "FAILED", "CANCELLED"}

violation contains make_diag_full("pf-glue-trigger-condition-crawl-state", "ERROR", name,
	sprintf("Properties.Predicate.Conditions.%d.CrawlState", [i]),
	sprintf("Condition CrawlState '%v' is not a crawler state a trigger can watch; CreateTrigger fails with \"CrawlerState should be any of: [SUCCEEDED, FAILED, CANCELLED]\"", [s]),
	"Use SUCCEEDED, FAILED or CANCELLED",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateTrigger.html") if {
	some name in resources_of_type("AWS::Glue::Trigger")
	some i, c in _pf_gluelib_conditions(name)
	is_object(c)
	s := object.get(c, "CrawlState", null)
	_pf_gluelib_lit(s)
	not s in _pf_gluetcs_states
}
