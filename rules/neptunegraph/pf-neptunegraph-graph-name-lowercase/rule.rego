package cdk_preflight

import rego.v1

# API モデル（neptune-graph 2023-11-29 GraphName）: (?!g-)[a-z][a-z0-9]*(-[a-z0-9]+)*、1-63 文字。
# 長さ・先頭が英字・末尾/連続ハイフンは同梱エンジンのスキーマ（F3031 / F3033）が止める
# （2026-09-22 guard）。スキーマのパターンが通してしまう大文字と g- 接頭辞だけを見る。
_pf_ngname_lit(name) := g if {
	g := resolve(name, "Properties.GraphName")
	is_string(g)
	not input.resources[g]
}

violation contains make_diag_full("pf-neptunegraph-graph-name-lowercase", "ERROR", name,
	"Properties.GraphName",
	sprintf("GraphName '%s' contains uppercase letters; Neptune Analytics accepts only lowercase letters, digits and hyphens", [g]),
	"Use lowercase letters, digits and hyphens only",
	"https://docs.aws.amazon.com/neptune-analytics/latest/apiref/API_CreateGraph.html") if {
	some name in resources_of_type("AWS::NeptuneGraph::Graph")
	g := _pf_ngname_lit(name)
	regex.match(`[A-Z]`, g)
}

violation contains make_diag_full("pf-neptunegraph-graph-name-lowercase", "ERROR", name,
	"Properties.GraphName",
	sprintf("GraphName '%s' starts with 'g-', which Neptune Analytics reserves for graph identifiers", [g]),
	"Pick a name that does not start with g-",
	"https://docs.aws.amazon.com/neptune-analytics/latest/apiref/API_CreateGraph.html") if {
	some name in resources_of_type("AWS::NeptuneGraph::Graph")
	g := _pf_ngname_lit(name)
	startswith(g, "g-")
}
