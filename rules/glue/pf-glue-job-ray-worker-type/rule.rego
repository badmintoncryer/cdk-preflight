package cdk_preflight

import rego.v1

# Kept for the message it produces, not because a Ray job can still be
# created: CreateJob checks the worker type first and names it, which is
# the more useful diagnostic of the two failures a glueray job now hits.
violation contains make_diag_full("pf-glue-job-ray-worker-type", "ERROR", name,
	"Properties.WorkerType",
	sprintf("WorkerType %v on a glueray job; Ray runs on Z.2X workers only", [wt]),
	"Set WorkerType to Z.2X (note that Glue Ray is deprecated and new Ray jobs are rejected)",
	"https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-jobs-job.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	_pf_gluelib_command_name(name) == "glueray"
	wt := _pf_gluelib_worker_type(name)
	wt != "Z.2X"
}
