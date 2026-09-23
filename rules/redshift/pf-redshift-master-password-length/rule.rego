package cdk_preflight

import rego.v1

# The upper end (64) is held by the engine schema (F3033); only the lower end is judged here.
violation contains make_diag_full("pf-redshift-master-password-length", "ERROR", name,
	"Properties.MasterUserPassword",
	sprintf("MasterUserPassword is %v characters, shorter than 8; CreateCluster rejects it (\"Invalid master password. Password should be atleast 8 characters long.\")", [count(pw)]),
	"Use a password of 8 to 64 characters, or use ManageMasterPassword",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	pw := _pf_redshiftlib_str(name, "MasterUserPassword")
	is_string(pw)
	count(pw) < 8
}
