package cdk_preflight

import rego.v1

# DynamoDB requires an exact match: every AttributeDefinitions entry must be
# used by the table key schema or an index key schema. The engine's E3039
# checks the opposite direction only (key attribute not defined), so the
# classic "removed a GSI, left the attribute definition" mistake sails through.

_pf_ddbadu_table_keys(name) := {a |
	some it in flatten_list(name, "Properties.KeySchema")
	a := object.get(it.value, "AttributeName", null)
	is_string(a)
}

_pf_ddbadu_index_keys(name, prop) := {a |
	some ix in flatten_list(name, sprintf("Properties.%s", [prop]))
	some k in object.get(ix.value, "KeySchema", [])
	a := object.get(k, "AttributeName", null)
	is_string(a)
}

_pf_ddbadu_used(name) := ((_pf_ddbadu_table_keys(name) |
	_pf_ddbadu_index_keys(name, "GlobalSecondaryIndexes")) |
	_pf_ddbadu_index_keys(name, "LocalSecondaryIndexes"))

# Any unresolvable AttributeName in a key schema means the used-set is
# incomplete, so the rule must stay silent rather than guess.
_pf_ddbadu_unresolvable(name) if {
	some it in flatten_list(name, "Properties.KeySchema")
	not is_string(object.get(it.value, "AttributeName", null))
}

_pf_ddbadu_unresolvable(name) if {
	some prop in ["GlobalSecondaryIndexes", "LocalSecondaryIndexes"]
	some ix in flatten_list(name, sprintf("Properties.%s", [prop]))
	some k in object.get(ix.value, "KeySchema", [])
	not is_string(object.get(k, "AttributeName", null))
}

violation contains make_diag_full("pf-dynamodb-attribute-definitions-usage", "ERROR", name,
	sprintf("Properties.AttributeDefinitions.%d", [d.index]),
	sprintf("Attribute '%s' is defined but used by no key schema; DynamoDB requires an exact match and fails with \"Number of attributes in KeySchema does not exactly match number of attributes defined in AttributeDefinitions\"", [attr]),
	"Remove the unused definition (non-key attributes such as a TTL attribute must NOT be declared), or add the index that uses it",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-table.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	not _pf_ddbadu_unresolvable(name)
	some d in flatten_list(name, "Properties.AttributeDefinitions")
	attr := object.get(d.value, "AttributeName", null)
	is_string(attr)
	not attr in _pf_ddbadu_used(name)
}
