package cdk_preflight

import rego.v1

# Anything outside printable ASCII 0x21-0x7E (which already excludes the space) or one
# of the six characters the service names. Dynamic references and tokens are not judged.
violation contains make_diag_full("pf-redshift-master-password-charset", "ERROR", name,
	"Properties.MasterUserPassword",
	"MasterUserPassword contains a character Redshift forbids; CreateCluster rejects it (\"Only printable ASCII characters except for '/', '@', '\"', ' ', '\\', ''' may be used.\")",
	"Remove /, @, double quotes, single quotes, backslashes, spaces and non-ASCII characters, or use ManageMasterPassword",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	pw := _pf_redshiftlib_str(name, "MasterUserPassword")
	regex.match(`[^!-~]|[/@"'\\]`, pw)
}
