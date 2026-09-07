package cdk_preflight

import rego.v1

_pf_leddn_fix := "Set DatabaseName alongside CollectionName"

_pf_leddn_url := "https://docs.aws.amazon.com/lambda/latest/dg/with-documentdb.html"

violation contains make_diag_full("pf-lambda-esm-docdb-database-name-required", "ERROR", name,
	"Properties.DocumentDBEventSourceConfig.DatabaseName",
	"CollectionName without DatabaseName; a collection is only addressable inside a database, so the mapping create is rejected",
	_pf_leddn_fix, _pf_leddn_url) if {
	some name in _pf_lam_esm
	cfg := _pf_lam_obj(_pf_lam_props(name), "DocumentDBEventSourceConfig")
	_pf_lam_has_key(cfg, "CollectionName")
	not _pf_lam_has_key(cfg, "DatabaseName")
}
