package cdk_preflight

import rego.v1

# Claim scope: first character only (the API doc also says 1-63 letters or numbers, but only
# the leading digit was probed; the charset and length stay silent).
violation contains make_diag_full("pf-docdb-username-first-char-letter", "ERROR", name,
	"Properties.MasterUsername",
	sprintf("MasterUsername '%s' does not start with a letter; DocumentDB rejects it (\"Invalid master user name\")", [u]),
	"Start the master user name with a letter",
	"https://docs.aws.amazon.com/documentdb/latest/developerguide/API_CreateDBCluster.html") if {
	some name in _pf_docdb_clusters
	u := _pf_docdb_lit(name, "Properties.MasterUsername")
	not regex.match(`^[A-Za-z]`, u)
}
