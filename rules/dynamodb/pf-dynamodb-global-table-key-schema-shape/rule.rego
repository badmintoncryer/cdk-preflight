package cdk_preflight

import rego.v1

# pf-dynamodb-key-schema-shape covers AWS::DynamoDB::Table only; the same
# CreateTable validation applies to a global table's key schema.
_pf_ddbgks_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-globaltable.html"

_pf_ddbgks_type(name, i) := kt if {
	some it in flatten_list(name, "Properties.KeySchema")
	it.index == i
	kt := object.get(it.value, "KeyType", null)
}

violation contains make_diag_full("pf-dynamodb-global-table-key-schema-shape", "ERROR", name,
	"Properties.KeySchema.0.KeyType",
	sprintf("The first KeySchema element must be HASH, got '%s'; CreateTable fails with \"Invalid KeySchema: The first KeySchemaElement is not a HASH key type\"", [kt]),
	"Put the partition key (KeyType HASH) first and the optional sort key (RANGE) second",
	_pf_ddbgks_url) if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	kt := _pf_ddbgks_type(name, 0)
	is_string(kt)
	kt != "HASH"
}

violation contains make_diag_full("pf-dynamodb-global-table-key-schema-shape", "ERROR", name,
	"Properties.KeySchema.1.KeyType",
	sprintf("The second KeySchema element must be RANGE, got '%s'; CreateTable fails with \"Invalid KeySchema: The second KeySchemaElement is not a RANGE key type\"", [kt]),
	"Use exactly one HASH element, optionally followed by one RANGE element",
	_pf_ddbgks_url) if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	kt := _pf_ddbgks_type(name, 1)
	is_string(kt)
	kt != "RANGE"
}

violation contains make_diag_full("pf-dynamodb-global-table-key-schema-shape", "ERROR", name,
	"Properties.KeySchema",
	sprintf("KeySchema can hold at most 2 elements (HASH + optional RANGE), got %d", [n]),
	"Model extra access patterns as global or local secondary indexes instead",
	_pf_ddbgks_url) if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	n := count(flatten_list(name, "Properties.KeySchema"))
	n > 2
}
