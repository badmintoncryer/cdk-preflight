package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-query-definition-log-groups-max", "ERROR", name,
	"Properties.LogGroupNames",
	sprintf("The query definition names %d log groups; PutQueryDefinition fails with \"Too many log groups specified\"", [n]),
	"Keep the saved query to 50 log groups",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-logs-querydefinition.html") if {
	some name in resources_of_type("AWS::Logs::QueryDefinition")
	items := [x | some x in flatten_list(name, "Properties.LogGroupNames")]
	n := count(items)
	n > 50
}
