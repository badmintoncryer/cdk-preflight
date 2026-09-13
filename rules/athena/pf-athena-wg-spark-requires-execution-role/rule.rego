package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-athena-wg-spark-requires-execution-role", "ERROR", name,
	"Properties.WorkGroupConfiguration.ExecutionRole",
	sprintf("the workgroup selects '%v' but sets no ExecutionRole; CreateWorkGroup fails with \"ExecutionRole is null or empty\"", [ev]),
	"Set WorkGroupConfiguration.ExecutionRole to the IAM role the Spark calculations run as",
	"https://docs.aws.amazon.com/athena/latest/APIReference/API_WorkGroupConfiguration.html") if {
	some name in resources_of_type("AWS::Athena::WorkGroup")
	cfg := _pf_athlib_wgcfg(name)
	ev := object.get(_pf_athlib_obj(cfg, "EngineVersion"), "SelectedEngineVersion", "")
	is_string(ev)
	startswith(ev, "PySpark")
	not _pf_athlib_has(cfg, "ExecutionRole")
}
