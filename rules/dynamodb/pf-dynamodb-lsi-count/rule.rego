package cdk_preflight

import rego.v1

# Unlike the GSI limit this one is a hard limit: it cannot be raised.
violation contains make_diag_full("pf-dynamodb-lsi-count", "ERROR", name,
	"Properties.LocalSecondaryIndexes",
	sprintf("The table declares %d local secondary indexes; CreateTable fails with \"Number of LocalSecondaryIndexes exceeds per-table limit of 5\"", [n]),
	"Keep LocalSecondaryIndexes at 5 or fewer (this limit cannot be raised); model the rest as global secondary indexes",
	"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html") if {
	some name in resources_of_type("AWS::DynamoDB::Table")
	n := count(flatten_list(name, "Properties.LocalSecondaryIndexes"))
	n > 5
}
