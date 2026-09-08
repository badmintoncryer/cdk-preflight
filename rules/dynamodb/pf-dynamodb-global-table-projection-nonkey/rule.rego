package cdk_preflight

import rego.v1

# pf-dynamodb-gsi-projection-nonkey covers AWS::DynamoDB::Table only. Both
# index kinds are checked here.
_pf_ddbgpj_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-globaltable-projection.html"

violation contains make_diag_full("pf-dynamodb-global-table-projection-nonkey", "ERROR", name,
	sprintf("Properties.%s.%d.Projection", [prop, ix.index]),
	sprintf("Index '%s' uses ProjectionType INCLUDE without NonKeyAttributes; CreateTable fails with \"ProjectionType is INCLUDE, but NonKeyAttributes is not specified\"", [iname]),
	"List the projected attributes in NonKeyAttributes, or switch ProjectionType to ALL / KEYS_ONLY",
	_pf_ddbgpj_url) if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	some prop in ["GlobalSecondaryIndexes", "LocalSecondaryIndexes"]
	some ix in flatten_list(name, sprintf("Properties.%s", [prop]))
	proj := object.get(ix.value, "Projection", null)
	is_object(proj)
	object.get(proj, "ProjectionType", null) == "INCLUDE"
	count(object.get(proj, "NonKeyAttributes", [])) == 0
	iname := object.get(ix.value, "IndexName", "<unnamed>")
}

violation contains make_diag_full("pf-dynamodb-global-table-projection-nonkey", "ERROR", name,
	sprintf("Properties.%s.%d.Projection", [prop, ix.index]),
	sprintf("Index '%s' combines ProjectionType %s with NonKeyAttributes; CreateTable fails with \"ProjectionType is %s, but NonKeyAttributes is specified\"", [iname, pt, pt]),
	"Drop NonKeyAttributes, or switch ProjectionType to INCLUDE",
	_pf_ddbgpj_url) if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	some prop in ["GlobalSecondaryIndexes", "LocalSecondaryIndexes"]
	some ix in flatten_list(name, sprintf("Properties.%s", [prop]))
	proj := object.get(ix.value, "Projection", null)
	is_object(proj)
	pt := object.get(proj, "ProjectionType", null)
	is_string(pt)
	pt != "INCLUDE"
	count(object.get(proj, "NonKeyAttributes", [])) > 0
	iname := object.get(ix.value, "IndexName", "<unnamed>")
}
