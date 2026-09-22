package cdk_preflight

import rego.v1

# Only a literal EngineVersion with a numeric major is judged; an absent EngineVersion
# defaults to the latest major (iopt1-capable) and stays silent.
violation contains make_diag_full("pf-docdb-storage-type-engine-version", "ERROR", name,
	"Properties.StorageType",
	sprintf("StorageType iopt1 is not supported for engine version %s; DocumentDB needs 5.0 or later (\"The iopt1 storage type isn't supported for the 4.0.0 DB engine version.\")", [ver]),
	"Use EngineVersion 5.0.0 or later, or StorageType standard",
	"https://docs.aws.amazon.com/documentdb/latest/developerguide/db-instance-classes.html") if {
	some name in _pf_docdb_clusters
	st := _pf_docdb_lit(name, "Properties.StorageType")
	lower(st) == "iopt1"
	ver := _pf_docdb_lit(name, "Properties.EngineVersion")
	regex.match(`^[1-9][0-9]*(\.[0-9]+)*$`, ver)
	parts := split(ver, ".")
	major := to_number(parts[0])
	major < 5
}
