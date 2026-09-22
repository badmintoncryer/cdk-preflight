package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-docdb-manage-master-password-exclusive", "ERROR", name,
	"Properties.ManageMasterUserPassword",
	"ManageMasterUserPassword is true together with MasterUserPassword (\"MasterUserPassword and ManageMasterUserPassword are mutually exclusive. Specify only one of these parameters.\")",
	"Keep only one of the two",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-docdb-dbcluster.html") if {
	some name in _pf_docdb_clusters
	_pf_docdb_true(name, "ManageMasterUserPassword")
	_pf_docdb_has(name, "MasterUserPassword")
}
