package cdk_preflight

import rego.v1

# Only the measured bound (minimum 3 characters) is enforced. The 255-char
# maximum and the character pattern were not measured. Note resolve() turns a
# Ref-to-resource into the target's logical ID; a logical ID short enough to
# trip this rule while feeding a TableName is treated as the bug it almost
# certainly is.
violation contains make_diag_full("pf-dynamodb-table-name-length", "ERROR", name,
	"Properties.TableName",
	sprintf("TableName '%s' is shorter than 3 characters; CreateTable fails with \"Member must have length greater than or equal to 3\"", [tn]),
	"Use a table name of at least 3 characters, or omit TableName and let CloudFormation generate one",
	"https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_CreateTable.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	tn := resolve(name, "Properties.TableName")
	is_string(tn)
	count(tn) < 3
}
