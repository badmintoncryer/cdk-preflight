package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-dynamodb-global-table-witness-region", "ERROR", name,
	sprintf("Properties.GlobalTableWitnesses.%d.Region", [w.index]),
	sprintf("The witness Region '%s' already holds a replica; a witness must be located in a different Region than the two replicas", [wr]),
	"Point the witness at the third Region of the set, the one without a replica",
	"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/V2globaltables_HowItWorks.html") if {
	some name in resources_of_type("AWS::DynamoDB::GlobalTable")
	some w in flatten_list(name, "Properties.GlobalTableWitnesses")
	wr := object.get(w.value, "Region", null)
	is_string(wr)
	wr in _pf_ddb_replica_regions(name)
}
