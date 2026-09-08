package cdk_preflight

import rego.v1

# pf-dynamodb-lsi-count covers AWS::DynamoDB::Table only. This limit is hard:
# it cannot be raised.
violation contains make_diag_full("pf-dynamodb-global-table-lsi-count", "ERROR", name,
	"Properties.LocalSecondaryIndexes",
	sprintf("The global table declares %d local secondary indexes; CreateTable fails with \"Number of LocalSecondaryIndexes exceeds per-table limit of 5\"", [n]),
	"Keep LocalSecondaryIndexes at 5 or fewer (this limit cannot be raised); model the rest as global secondary indexes",
	"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	n := count(flatten_list(name, "Properties.LocalSecondaryIndexes"))
	n > 5
}
