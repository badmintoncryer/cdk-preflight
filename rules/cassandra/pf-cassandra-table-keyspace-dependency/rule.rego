package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-table-keyspace-dependency", "ERROR", name, "Properties.KeyspaceName",
	sprintf("KeyspaceName %v is created by %v in this template, but nothing makes this resource wait for it; CloudFormation creates both in parallel and Keyspaces answers \"Keyspace %v does not exist\"", [v, k, v]),
	"Use {Ref: <keyspace>} for KeyspaceName (or add DependsOn on the keyspace)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cassandra-table.html#cfn-cassandra-table-keyspacename") if {
	some rt in ["AWS::Cassandra::Table", "AWS::Cassandra::Type"]
	some name in resources_of_type(rt)
	v := object.get(input.resources[name].properties, "KeyspaceName", null)
	is_string(v)
	some k in resources_of_type("AWS::Cassandra::Keyspace")
	object.get(input.resources[k].properties, "KeyspaceName", null) == v
	deps := _pf_cass_deps(name)
	not k in deps
}
