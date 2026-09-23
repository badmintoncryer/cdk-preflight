package cdk_preflight

import rego.v1

# API モデル（neptune-graph 2023-11-29 VectorSearchDimension）: min 1 / max 65536。
# 同梱エンジンのスキーマはどちらの端も持たない（2026-09-22 guard: 0 と 65537 が clean）。
_pf_ngvdim_out(n) if n < 1

_pf_ngvdim_out(n) if n > 65536

violation contains make_diag_full("pf-neptunegraph-vector-dimension-range", "ERROR", name,
	"Properties.VectorSearchConfiguration.VectorSearchDimension",
	sprintf("VectorSearchDimension %v is outside 1-65536; Neptune Analytics rejects the graph at create time", [n]),
	"Use a vector dimension between 1 and 65536",
	"https://docs.aws.amazon.com/neptune-analytics/latest/apiref/API_CreateGraph.html") if {
	some name in resources_of_type("AWS::NeptuneGraph::Graph")
	n := to_number(resolve(name, "Properties.VectorSearchConfiguration.VectorSearchDimension"))
	_pf_ngvdim_out(n)
}
