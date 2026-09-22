package cdk_preflight

import rego.v1

# 1.0.x / 1.1.x は neptune1、1.2.0.0 以降は neptune1.<minor>（CFN の Family の説明）。
# 版が書かれていない（既定＝最新）クラスタや Ref で渡された版は判定しない。
_pf_nepcpg_want(v) := "neptune1" if {
	is_string(v)
	regex.match(`^1\.[01]\.`, v)
}

_pf_nepcpg_want(v) := sprintf("neptune1.%s", [p[1]]) if {
	is_string(v)
	regex.match(`^1\.([2-9]|[1-9][0-9]+)\.`, v)
	p := split(v, ".")
}

violation contains make_diag_full("pf-neptune-cpg-family-engine-version", "ERROR", name,
	"Properties.DBClusterParameterGroupName",
	sprintf("Cluster parameter group %v has Family %v, but EngineVersion %v needs %v (\"The Parameter Group ... with DBParameterGroupFamily neptune1.2 cannot be used for this instance. Please use a Parameter Group with DBParameterGroupFamily neptune1.3\")", [pg, fam, v, want]),
	"Match the parameter group family to the engine version",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptune-dbclusterparametergroup.html") if {
	some name in resources_of_type("AWS::Neptune::DBCluster")
	pg := resolve(name, "Properties.DBClusterParameterGroupName")
	is_string(pg)
	input.resources[pg].resourceType == "AWS::Neptune::DBClusterParameterGroup"
	f0 := resolve(pg, "Properties.Family")
	is_string(f0)
	fam := lower(f0)
	v := resolve(name, "Properties.EngineVersion")
	want := _pf_nepcpg_want(v)
	fam != want
}
