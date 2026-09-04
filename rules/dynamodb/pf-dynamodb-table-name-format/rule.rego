package cdk_preflight

import rego.v1

_pf_ddbname_bad contains [name, n] if {
	some t in {"AWS::DynamoDB::Table", "AWS::DynamoDB::GlobalTable"}
	some name in resources_of_type(t)
	n := resolve(name, "Properties.TableName")
	is_string(n)
	not regex.match(`^[a-zA-Z0-9_.-]{1,255}$`, n)
}

violation contains make_diag_full("pf-dynamodb-table-name-format", "ERROR", name,
	"Properties.TableName",
	sprintf("TableName '%s' is rejected: DynamoDB accepts only letters, numbers, underscore, dot and hyphen, up to 255 characters", [n]),
	"Rename the table using [a-zA-Z0-9_.-] within 255 characters",
	"https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html") if {
	some [name, n] in _pf_ddbname_bad
}
