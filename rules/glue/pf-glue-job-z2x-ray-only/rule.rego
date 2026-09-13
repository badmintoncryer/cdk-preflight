package cdk_preflight

import rego.v1

# Glue Ray is deprecated, so glueray + Z.2X is itself rejected now (the
# account-level message, not this one). This rule stays scoped to the
# non-Ray commands, where the worker-type list is the reason for the
# failure.
violation contains make_diag_full("pf-glue-job-z2x-ray-only", "ERROR", name,
	"Properties.WorkerType",
	sprintf("WorkerType Z.2X on a %v job; Z.2X exists only for Ray (glueray) jobs", [cmd]),
	"Pick a worker type the command supports (G.1X and up for Spark)",
	"https://docs.aws.amazon.com/glue/latest/dg/worker-types.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	_pf_gluelib_worker_type(name) == "Z.2X"
	cmd := _pf_gluelib_command_name(name)
	cmd != "glueray"
}
