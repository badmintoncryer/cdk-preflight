package cdk_preflight

import rego.v1

_pf_mdbport_url := "https://docs.aws.amazon.com/memorydb/latest/APIReference/API_CreateCluster.html"

_pf_mdbport_fix := "Pick a port in 1150-8004 or 8006-65535 (8005 is reserved)"

violation contains make_diag_full("pf-memorydb-port", "ERROR", name,
	"Properties.Port",
	sprintf("Port %v is outside the accepted range; CreateCluster fails with \"Invalid endpoint port: %v. Valid range is 1150-8004,8006-65535\"", [p, p]),
	_pf_mdbport_fix, _pf_mdbport_url) if {
	some name in resources_of_type("AWS::MemoryDB::Cluster")
	p := to_number(resolve(name, "Properties.Port"))
	not _pf_cachelib_port_ok(p)
}
