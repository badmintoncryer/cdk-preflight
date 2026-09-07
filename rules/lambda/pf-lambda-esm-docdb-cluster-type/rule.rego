package cdk_preflight

import rego.v1

_pf_ledct_fix := "Point the mapping at an instance-based (regional) DocumentDB cluster"

_pf_ledct_url := "https://docs.aws.amazon.com/lambda/latest/dg/with-documentdb.html"

violation contains make_diag_full("pf-lambda-esm-docdb-cluster-type", "ERROR", name,
	"Properties.EventSourceArn",
	"the source ARN names the 'docdb-elastic' service; Lambda reads change streams only from instance-based DocumentDB clusters, not elastic ones",
	_pf_ledct_fix, _pf_ledct_url) if {
	some name in _pf_lam_esm
	_pf_lam_has(name, "DocumentDBEventSourceConfig")
	parts := _pf_lam_arn(resolve(name, "Properties.EventSourceArn"))
	parts[2] == "docdb-elastic"
}
