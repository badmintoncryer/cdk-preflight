package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-replica-read-capacity-requires-provisioned", "ERROR", name, sprintf("Properties.ReplicaSpecifications.%d", [i]),
	"the replica sets ReadCapacityUnits / ReadCapacityAutoScaling but the table is ON_DEMAND (the default); Keyspaces answers \"Set throughput_mode explicitly as PROVISIONED\"",
	"Remove the replica read capacity settings, or make the table PROVISIONED",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/tables-mrr-autoscaling.html") if {
	some name in resources_of_type("AWS::Cassandra::Table")
	_pf_cass_mode(name) == "ON_DEMAND"
	reps := object.get(input.resources[name].properties, "ReplicaSpecifications", null)
	is_array(reps)
	some i, r in reps
	is_object(r)
	some k in ["ReadCapacityUnits", "ReadCapacityAutoScaling"]
	object.get(r, k, null) != null
}
