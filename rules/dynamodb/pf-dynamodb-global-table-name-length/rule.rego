package cdk_preflight

import rego.v1

# pf-dynamodb-table-name-length covers AWS::DynamoDB::Table only. Only the
# measured minimum is enforced; the 255-char maximum and the character
# pattern belong to pf-dynamodb-table-name-format.
violation contains make_diag_full("pf-dynamodb-global-table-name-length", "ERROR", name,
	"Properties.TableName",
	sprintf("TableName '%s' is shorter than 3 characters; CreateTable fails with \"Member must have length greater than or equal to 3\"", [tn]),
	"Use a table name of at least 3 characters, or omit TableName and let CloudFormation generate one",
	"https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	tn := resolve(name, "Properties.TableName")
	is_string(tn)
	count(tn) < 3
}
