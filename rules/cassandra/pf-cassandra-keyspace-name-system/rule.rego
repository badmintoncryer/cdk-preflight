package cdk_preflight

import rego.v1

_pf_cassksys_names := {"system", "system_schema", "system_schema_mcs", "system_multiregion_info"}

violation contains make_diag_full("pf-cassandra-keyspace-name-system", "ERROR", name, "Properties.KeyspaceName",
	sprintf("KeyspaceName %v is a system keyspace that Keyspaces owns in every account", [n]),
	"Pick another keyspace name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cassandra-keyspace.html#cfn-cassandra-keyspace-keyspacename") if {
	some name in resources_of_type("AWS::Cassandra::Keyspace")
	n := object.get(input.resources[name].properties, "KeyspaceName", null)
	is_string(n)
	n in _pf_cassksys_names
}
