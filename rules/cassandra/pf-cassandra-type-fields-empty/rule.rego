package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-type-fields-empty", "ERROR", name, "Properties.Fields",
	"Fields is empty; CreateType requires at least one field (\"Member must have length greater than or equal to 1\")",
	"Declare at least one field",
	"https://docs.aws.amazon.com/keyspaces/latest/APIReference/API_CreateType.html") if {
	some name in resources_of_type("AWS::Cassandra::Type")
	fs := object.get(input.resources[name].properties, "Fields", null)
	is_array(fs)
	count(fs) == 0
}
