package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-field-index-fields-max", "ERROR", name,
	"Properties.FieldIndexPolicies",
	sprintf("The field index policy lists %d fields; PutIndexPolicy fails with \"Policy document contains more than 20 fields.\"", [n]),
	"Index at most 20 fields per log group",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-logs-loggroup.html") if {
	some name in resources_of_type("AWS::Logs::LogGroup")
	some item in flatten_list(name, "Properties.FieldIndexPolicies")
	pol := item.value
	is_object(pol)
	fields := object.get(pol, "Fields", null)
	is_array(fields)
	n := count(fields)
	n > 20
}
