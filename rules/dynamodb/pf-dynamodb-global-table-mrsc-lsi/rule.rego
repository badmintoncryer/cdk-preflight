package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-dynamodb-global-table-mrsc-lsi", "ERROR", name,
	"Properties.LocalSecondaryIndexes",
	sprintf("The global table declares %d local secondary indexes with MultiRegionConsistency STRONG; MRSC does not support LSIs", [n]),
	"Model the access pattern as a global secondary index, or use multi-Region eventual consistency (MREC)",
	"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	_pf_ddb_mrsc(name)
	n := count(flatten_list(name, "Properties.LocalSecondaryIndexes"))
	n > 0
}
