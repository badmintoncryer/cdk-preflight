package cdk_preflight

import rego.v1

# RegionList 省略も「現リージョンを含まない」と同じ拒否文になる（2026-10-01 実測）ので 1 本で見る。
# RegionList ありの枝は deploy_region が分かるときだけ、要素が全部文字列リテラルのときだけ鳴る。
violation contains make_diag_full("pf-cassandra-keyspace-regionlist-includes-current", "ERROR", name, "Properties.ReplicationSpecification",
	"ReplicationStrategy is MULTI_REGION but RegionList is missing; Keyspaces answers \"Replication regions must include the current region\"",
	"Add a RegionList with the deployment Region and at least one other Region",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cassandra-keyspace.html#cfn-cassandra-keyspace-replicationspecification") if {
	some name in resources_of_type("AWS::Cassandra::Keyspace")
	_pf_cass_mr(name)
	rs := input.resources[name].properties.ReplicationSpecification
	object.get(rs, "RegionList", null) == null
}

violation contains make_diag_full("pf-cassandra-keyspace-regionlist-includes-current", "ERROR", name, "Properties.ReplicationSpecification.RegionList",
	sprintf("RegionList %v does not include the deployment Region %v; Keyspaces answers \"Replication regions must include the current region\"", [rl, region]),
	"Add the deployment Region (or a Ref to AWS::Region) to RegionList",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cassandra-keyspace.html#cfn-cassandra-keyspace-replicationspecification") if {
	some name in resources_of_type("AWS::Cassandra::Keyspace")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	_pf_cass_mr(name)
	rl := input.resources[name].properties.ReplicationSpecification.RegionList
	is_array(rl)
	count(rl) > 0
	every r in rl { is_string(r) }
	not region in rl
}
