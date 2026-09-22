package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-docdb-master-password-length", "ERROR", name,
	"Properties.MasterUserPassword",
	sprintf("MasterUserPassword is %v characters; DocumentDB requires at least 8 (\"The parameter MasterUserPassword is not a valid password because it is shorter than 8 characters.\")", [count(pw)]),
	"Use 8 or more characters, or ManageMasterUserPassword / a Secrets Manager reference",
	"https://docs.aws.amazon.com/documentdb/latest/developerguide/API_CreateDBCluster.html") if {
	some name in _pf_docdb_clusters
	pw := _pf_docdb_lit(name, "Properties.MasterUserPassword")
	is_string(pw)
	count(pw) < 8
}
