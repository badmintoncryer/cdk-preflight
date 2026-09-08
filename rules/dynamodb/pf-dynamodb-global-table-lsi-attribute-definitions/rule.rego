package cdk_preflight

import rego.v1

# pf-dynamodb-lsi-attribute-definitions covers AWS::DynamoDB::Table only.
_pf_ddbgla_defs(name) := {a |
	some d in flatten_list(name, "Properties.AttributeDefinitions")
	a := object.get(d.value, "AttributeName", null)
	is_string(a)
}

_pf_ddbgla_defs_resolvable(name) if {
	every d in [x | some x in flatten_list(name, "Properties.AttributeDefinitions")] {
		is_string(object.get(d.value, "AttributeName", null))
	}
}

violation contains make_diag_full("pf-dynamodb-global-table-lsi-attribute-definitions", "ERROR", name,
	sprintf("Properties.LocalSecondaryIndexes.%d.KeySchema", [l.index]),
	sprintf("LSI key attribute '%s' is not defined in AttributeDefinitions; CreateTable fails with \"An attribute referenced in a KeySchema element is not defined in AttributeDefinitions\"", [attr]),
	"Add the attribute to AttributeDefinitions (and nowhere else: only key attributes belong there)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-globaltable-localsecondaryindex.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	count(_pf_ddbgla_defs(name)) > 0
	_pf_ddbgla_defs_resolvable(name)
	some l in flatten_list(name, "Properties.LocalSecondaryIndexes")
	some k in object.get(l.value, "KeySchema", [])
	attr := object.get(k, "AttributeName", null)
	is_string(attr)
	not attr in _pf_ddbgla_defs(name)
}
