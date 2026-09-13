package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-glue-trigger-action-job-or-crawler", "ERROR", name,
	sprintf("Properties.Actions.%d", [item.index]),
	"A trigger action sets both JobName and CrawlerName; CreateTrigger fails with \"Both JobName or CrawlerName cannot be set together in an action\"",
	"Split the action in two: one action with JobName, another with CrawlerName",
	"https://docs.aws.amazon.com/glue/latest/webapi/API_CreateTrigger.html") if {
	some name in resources_of_type("AWS::Glue::Trigger")
	some item in flatten_list(name, "Properties.Actions")
	is_object(item.value)
	object.get(item.value, "JobName", "__pf_absent") != "__pf_absent"
	object.get(item.value, "CrawlerName", "__pf_absent") != "__pf_absent"
}
