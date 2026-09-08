package cdk_preflight

import rego.v1

# The engine's E3039 checks key attributes against AttributeDefinitions for
# AWS::DynamoDB::Table only, and never the unused direction (measured
# 2026-09-08, 1.7.0-beta). LSI key attributes are covered by
# pf-dynamodb-global-table-lsi-attribute-definitions.
_pf_ddbgad_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-globaltable.html"

_pf_ddbgad_defs(name) := {a |
	some d in flatten_list(name, "Properties.AttributeDefinitions")
	a := object.get(d.value, "AttributeName", null)
	is_string(a)
}

_pf_ddbgad_table_keys(name) := {a |
	some it in flatten_list(name, "Properties.KeySchema")
	a := object.get(it.value, "AttributeName", null)
	is_string(a)
}

_pf_ddbgad_index_keys(name, prop) := {a |
	some ix in flatten_list(name, sprintf("Properties.%s", [prop]))
	some k in object.get(ix.value, "KeySchema", [])
	a := object.get(k, "AttributeName", null)
	is_string(a)
}

_pf_ddbgad_used(name) := ((_pf_ddbgad_table_keys(name) |
	_pf_ddbgad_index_keys(name, "GlobalSecondaryIndexes")) |
	_pf_ddbgad_index_keys(name, "LocalSecondaryIndexes"))

# Any unresolvable name anywhere makes the comparison incomplete — stay silent.
_pf_ddbgad_unresolvable(name) if {
	some it in flatten_list(name, "Properties.KeySchema")
	not is_string(object.get(it.value, "AttributeName", null))
}

_pf_ddbgad_unresolvable(name) if {
	some prop in ["GlobalSecondaryIndexes", "LocalSecondaryIndexes"]
	some ix in flatten_list(name, sprintf("Properties.%s", [prop]))
	some k in object.get(ix.value, "KeySchema", [])
	not is_string(object.get(k, "AttributeName", null))
}

_pf_ddbgad_unresolvable(name) if {
	some d in flatten_list(name, "Properties.AttributeDefinitions")
	not is_string(object.get(d.value, "AttributeName", null))
}

violation contains make_diag_full("pf-dynamodb-global-table-attribute-definitions", "ERROR", name,
	"Properties.KeySchema",
	sprintf("Key attribute '%s' is not defined in AttributeDefinitions; CreateTable fails with \"An attribute referenced in a KeySchema element is not defined in AttributeDefinitions\"", [attr]),
	"Declare every key attribute in AttributeDefinitions with its type (S, N or B)",
	_pf_ddbgad_url) if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	not _pf_ddbgad_unresolvable(name)
	some attr in _pf_ddbgad_table_keys(name)
	not attr in _pf_ddbgad_defs(name)
}

violation contains make_diag_full("pf-dynamodb-global-table-attribute-definitions", "ERROR", name,
	"Properties.GlobalSecondaryIndexes",
	sprintf("GSI key attribute '%s' is not defined in AttributeDefinitions; CreateTable fails with \"An attribute referenced in a KeySchema element is not defined in AttributeDefinitions\"", [attr]),
	"Declare every index key attribute in AttributeDefinitions with its type (S, N or B)",
	_pf_ddbgad_url) if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	not _pf_ddbgad_unresolvable(name)
	some attr in _pf_ddbgad_index_keys(name, "GlobalSecondaryIndexes")
	not attr in _pf_ddbgad_defs(name)
}

violation contains make_diag_full("pf-dynamodb-global-table-attribute-definitions", "ERROR", name,
	sprintf("Properties.AttributeDefinitions.%d", [d.index]),
	sprintf("Attribute '%s' is defined but used by no key schema; DynamoDB requires an exact match and fails with \"Number of attributes in KeySchema does not exactly match number of attributes defined in AttributeDefinitions\"", [attr]),
	"Remove the unused definition (non-key attributes such as a TTL attribute must NOT be declared), or add the index that uses it",
	_pf_ddbgad_url) if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	not _pf_ddbgad_unresolvable(name)
	some d in flatten_list(name, "Properties.AttributeDefinitions")
	attr := object.get(d.value, "AttributeName", null)
	is_string(attr)
	not attr in _pf_ddbgad_used(name)
}
