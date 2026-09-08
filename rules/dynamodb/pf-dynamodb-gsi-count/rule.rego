package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-dynamodb-gsi-count", "ERROR", name,
	"Properties.GlobalSecondaryIndexes",
	sprintf("The table declares %d global secondary indexes; CreateTable fails with \"GlobalSecondaryIndex count exceeds the per-table limit of 20\"", [n]),
	"Keep GlobalSecondaryIndexes at 20 or fewer, or raise the per-table quota before deploying",
	"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	n := count(flatten_list(name, "Properties.GlobalSecondaryIndexes"))
	n > 20
}
