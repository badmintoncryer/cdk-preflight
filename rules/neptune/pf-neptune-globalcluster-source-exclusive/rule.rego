package cdk_preflight

import rego.v1

# 既存クラスタから作る global cluster は Engine / EngineVersion / StorageEncrypted を
# ソースから継承するので、書くと拒否される（値は見ない。書かれているかだけ）。
_pf_nepgcx_inherited := {"Engine", "EngineVersion", "StorageEncrypted"}

violation contains make_diag_full("pf-neptune-globalcluster-source-exclusive", "ERROR", name,
	sprintf("Properties.%s", [k]),
	sprintf("%s is set together with SourceDBClusterIdentifier; Neptune inherits it from the source cluster and rejects the pair (\"When creating global cluster from existing db cluster, value for engineName should not be specified since it will be inherited from source cluster\")", [k]),
	"Remove Engine, EngineVersion and StorageEncrypted when SourceDBClusterIdentifier is set",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-neptune-globalcluster.html") if {
	some name in resources_of_type("AWS::Neptune::GlobalCluster")
	_pf_neptunelib_has(name, "SourceDBClusterIdentifier")
	some k in _pf_nepgcx_inherited
	_pf_neptunelib_has(name, k)
}
