package cdk_preflight

import rego.v1

_pf_docdbshs_url := "https://docs.aws.amazon.com/documentdb/latest/developerguide/API_ServerlessV2ScalingConfiguration.html"

_pf_docdbshs_bad(n) if {
	f := n * 2
	f != round(f)
}

violation contains make_diag_full("pf-docdb-serverless-half-step", "ERROR", name,
	"Properties.ServerlessV2ScalingConfiguration.MinCapacity",
	sprintf("MinCapacity %v is not a multiple of 0.5 (\"Serverless v2 capacity value 8.3 is not valid. It must be a multiple of 0.5.\")", [n]),
	"Round the capacity to a multiple of 0.5",
	_pf_docdbshs_url) if {
	some name in _pf_docdb_clusters
	n := to_number(resolve(name, "Properties.ServerlessV2ScalingConfiguration.MinCapacity"))
	_pf_docdbshs_bad(n)
}

violation contains make_diag_full("pf-docdb-serverless-half-step", "ERROR", name,
	"Properties.ServerlessV2ScalingConfiguration.MaxCapacity",
	sprintf("MaxCapacity %v is not a multiple of 0.5 (\"Serverless v2 capacity value 8.3 is not valid. It must be a multiple of 0.5.\")", [n]),
	"Round the capacity to a multiple of 0.5",
	_pf_docdbshs_url) if {
	some name in _pf_docdb_clusters
	n := to_number(resolve(name, "Properties.ServerlessV2ScalingConfiguration.MaxCapacity"))
	_pf_docdbshs_bad(n)
}
