package cdk_preflight

import rego.v1

_pf_mdbdt_url := "https://docs.aws.amazon.com/memorydb/latest/APIReference/API_CreateCluster.html"

_pf_mdbdt_fix := "Use an r6gd node type (db.r6gd.xlarge and larger) for data tiering, or drop DataTiering"

violation contains make_diag_full("pf-memorydb-data-tiering-node-type", "ERROR", name,
	"Properties.DataTiering",
	sprintf("data tiering is enabled on node type %s; CreateCluster fails with \"Data tiering is not supported for the node type %s.\"", [nt, nt]),
	_pf_mdbdt_fix, _pf_mdbdt_url) if {
	some name in resources_of_type("AWS::MemoryDB::Cluster")
	_pf_mdbdt_on(resolve(name, "Properties.DataTiering"))
	nt := resolve(name, "Properties.NodeType")
	_pf_cachelib_lit(nt)
	not _pf_cachelib_r6gd(nt)
}

# The property is typed as a string enum ("true" / "false") but a boolean
# reaches the template just as often.
_pf_mdbdt_on(v) if v == true

_pf_mdbdt_on(v) if v == "true"
