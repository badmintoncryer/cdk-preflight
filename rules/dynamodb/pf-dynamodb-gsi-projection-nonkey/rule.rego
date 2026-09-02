package cdk_preflight

import rego.v1

_pf_ddbgpn_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-table-projection.html"

# GSI projections only: the LSI shape and the KEYS_ONLY+NonKeyAttributes combo
# were not measured (issue #21).
violation contains make_diag_full("pf-dynamodb-gsi-projection-nonkey", "ERROR", name,
	sprintf("Properties.GlobalSecondaryIndexes.%d.Projection", [g.index]),
	sprintf("GSI '%s' uses ProjectionType INCLUDE without NonKeyAttributes; CreateTable fails with \"ProjectionType is INCLUDE, but NonKeyAttributes is not specified\"", [iname]),
	"List the projected attributes in NonKeyAttributes, or switch ProjectionType to ALL / KEYS_ONLY",
	_pf_ddbgpn_url) if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	some g in flatten_list(name, "Properties.GlobalSecondaryIndexes")
	proj := object.get(g.value, "Projection", null)
	is_object(proj)
	object.get(proj, "ProjectionType", null) == "INCLUDE"
	count(object.get(proj, "NonKeyAttributes", [])) == 0
	iname := object.get(g.value, "IndexName", "<unnamed>")
}

violation contains make_diag_full("pf-dynamodb-gsi-projection-nonkey", "ERROR", name,
	sprintf("Properties.GlobalSecondaryIndexes.%d.Projection", [g.index]),
	sprintf("GSI '%s' combines ProjectionType ALL with NonKeyAttributes; CreateTable fails with \"ProjectionType is ALL, but NonKeyAttributes is specified\"", [iname]),
	"Drop NonKeyAttributes (ALL already projects everything), or switch ProjectionType to INCLUDE",
	_pf_ddbgpn_url) if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	some g in flatten_list(name, "Properties.GlobalSecondaryIndexes")
	proj := object.get(g.value, "Projection", null)
	is_object(proj)
	object.get(proj, "ProjectionType", null) == "ALL"
	count(object.get(proj, "NonKeyAttributes", [])) > 0
	iname := object.get(g.value, "IndexName", "<unnamed>")
}
