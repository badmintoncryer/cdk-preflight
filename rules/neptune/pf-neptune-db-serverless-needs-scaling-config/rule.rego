package cdk_preflight

import rego.v1

# クロスリソース: インスタンスが db.serverless なら、同じテンプレートのクラスタは
# ServerlessScalingConfiguration を持っていなければならない。クラスタが import
# されている（Ref 先がテンプレートに無い）場合は判定しない。
violation contains make_diag_full("pf-neptune-db-serverless-needs-scaling-config", "ERROR", name,
	"Properties.DBInstanceClass",
	sprintf("DBInstanceClass is db.serverless but cluster %v declares no ServerlessScalingConfiguration; Neptune rejects the instance at create time", [cl]),
	"Add ServerlessScalingConfiguration (MinCapacity/MaxCapacity) to the DB cluster",
	"https://docs.aws.amazon.com/neptune/latest/userguide/neptune-serverless-capacity-scaling.html") if {
	some name in resources_of_type("AWS::Neptune::DBInstance")
	c := resolve(name, "Properties.DBInstanceClass")
	is_string(c)
	lower(c) == "db.serverless"
	cl := resolve(name, "Properties.DBClusterIdentifier")
	is_string(cl)
	input.resources[cl].resourceType == "AWS::Neptune::DBCluster"
	not _pf_neptunelib_has(cl, "ServerlessScalingConfiguration")
}
