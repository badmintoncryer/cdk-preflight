package cdk_preflight

import rego.v1

# Only the literal the API names. Redshift identifiers are case-insensitive, so the
# comparison folds case; the other MasterUsername constraints are not judged.
violation contains make_diag_full("pf-redshift-master-username-reserved-public", "ERROR", name,
	"Properties.MasterUsername",
	sprintf("MasterUsername '%s' is reserved; CreateCluster rejects it (\"The master username can't be named PUBLIC\")", [u]),
	"Pick another admin user name",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	u := _pf_redshiftlib_str(name, "MasterUsername")
	lower(u) == "public"
}
