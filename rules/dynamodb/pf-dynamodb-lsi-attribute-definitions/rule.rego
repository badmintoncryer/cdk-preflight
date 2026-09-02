package cdk_preflight

import rego.v1

# The engine's E3039 checks table and GSI key schemas against
# AttributeDefinitions but is blind to LocalSecondaryIndexes (measured
# 2026-09-02, 1.7.0-beta). This rule covers exactly that gap.

_pf_ddblad_defs(name) := {a |
	some d in flatten_list(name, "Properties.AttributeDefinitions")
	a := object.get(d.value, "AttributeName", null)
	is_string(a)
}

# If any definition's name is unresolvable the set is incomplete — stay silent.
_pf_ddblad_defs_resolvable(name) if {
	every d in [x | some x in flatten_list(name, "Properties.AttributeDefinitions")] {
		is_string(object.get(d.value, "AttributeName", null))
	}
}

violation contains make_diag_full("pf-dynamodb-lsi-attribute-definitions", "ERROR", name,
	sprintf("Properties.LocalSecondaryIndexes.%d.KeySchema", [l.index]),
	sprintf("LSI key attribute '%s' is not defined in AttributeDefinitions; CreateTable fails with \"An attribute referenced in a KeySchema element is not defined in AttributeDefinitions\"", [attr]),
	"Add the attribute to AttributeDefinitions (and nowhere else: only key attributes belong there)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-table-localsecondaryindex.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	count(_pf_ddblad_defs(name)) > 0
	_pf_ddblad_defs_resolvable(name)
	some l in flatten_list(name, "Properties.LocalSecondaryIndexes")
	some k in object.get(l.value, "KeySchema", [])
	attr := object.get(k, "AttributeName", null)
	is_string(attr)
	not attr in _pf_ddblad_defs(name)
}
