package cdk_preflight

import rego.v1

_pf_ddbdin_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-table.html"

# Duplicates within the same index list only; a GSI/LSI cross-list clash was
# not measured (issue #21).
violation contains make_diag_full("pf-dynamodb-duplicate-index-name", "ERROR", name,
	sprintf("Properties.%s.%d.IndexName", [prop, b.index]),
	sprintf("Index name '%s' is used more than once; CreateTable fails with \"Duplicate index name\"", [iname]),
	"Give every secondary index a unique IndexName",
	_pf_ddbdin_url) if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	some prop in ["GlobalSecondaryIndexes", "LocalSecondaryIndexes"]
	some a in flatten_list(name, sprintf("Properties.%s", [prop]))
	some b in flatten_list(name, sprintf("Properties.%s", [prop]))
	a.index < b.index
	iname := object.get(a.value, "IndexName", null)
	is_string(iname)
	object.get(b.value, "IndexName", null) == iname
}
