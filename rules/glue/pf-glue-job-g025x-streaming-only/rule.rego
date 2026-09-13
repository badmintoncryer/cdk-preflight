package cdk_preflight

import rego.v1

# G.025X is the low-volume streaming worker; batch ETL rejects it.
violation contains make_diag_full("pf-glue-job-g025x-streaming-only", "ERROR", name,
	"Properties.WorkerType",
	sprintf("WorkerType G.025X on a %v job; the quarter-DPU worker is for gluestreaming jobs only", [cmd]),
	"Use G.1X or larger, or change Command.Name to gluestreaming",
	"https://docs.aws.amazon.com/glue/latest/dg/worker-types.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	_pf_gluelib_worker_type(name) == "G.025X"
	cmd := _pf_gluelib_command_name(name)
	cmd != "gluestreaming"
}
