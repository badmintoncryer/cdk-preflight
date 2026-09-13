package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-athena-wg-managed-storage-xor-output-location", "ERROR", name,
	"Properties.WorkGroupConfiguration.ManagedQueryResultsConfiguration",
	"the workgroup enables managed query results and also sets ResultConfiguration; CreateWorkGroup fails with \"ManagedQueryResultsConfiguration and ResultConfiguration cannot be set together.\"",
	"Keep managed query result storage, or drop it and keep the ResultConfiguration output location",
	"https://docs.aws.amazon.com/athena/latest/APIReference/API_WorkGroupConfiguration.html") if {
	some name in resources_of_type("AWS::Athena::WorkGroup")
	cfg := _pf_athlib_wgcfg(name)
	object.get(_pf_athlib_obj(cfg, "ManagedQueryResultsConfiguration"), "Enabled", false) == true
	_pf_athlib_has(cfg, "ResultConfiguration")
}
