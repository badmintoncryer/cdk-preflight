package cdk_preflight

import rego.v1

_pf_ddbmrc_url := "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html"

violation contains make_diag_full("pf-dynamodb-global-table-mrsc-replica-count", "ERROR", name,
	"Properties.Replicas",
	sprintf("MultiRegionConsistency is STRONG but the table spans %d Regions (%d replicas + %d witnesses); MRSC requires exactly three", [total, nr, nw]),
	"Use three replicas, or two replicas and one witness",
	_pf_ddbmrc_url) if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	_pf_ddb_mrsc(name)
	nr := count(flatten_list(name, "Properties.Replicas"))
	nw := count(flatten_list(name, "Properties.GlobalTableWitnesses"))
	total := nr + nw
	total != 3
}

violation contains make_diag_full("pf-dynamodb-global-table-mrsc-replica-count", "ERROR", name,
	"Properties.Replicas",
	sprintf("MultiRegionConsistency is STRONG with only %d replica; MRSC needs two replicas plus a witness, or three replicas", [nr]),
	"Add a second replica (a witness cannot stand in for one)",
	_pf_ddbmrc_url) if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	_pf_ddb_mrsc(name)
	nr := count(flatten_list(name, "Properties.Replicas"))
	nr < 2
}
