package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jq-type-matches-ce-type", "ERROR", name,
	"Properties.JobQueueType",
	sprintf("an EKS job queue attaches the non-EKS compute environment %v (\"EKS job queue type must have EKS compute environment.\")", [cel]),
	"Attach an EKS compute environment, or drop JobQueueType: EKS",
	"https://docs.aws.amazon.com/batch/latest/userguide/job_queue_parameters.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	_pf_batch_qtype(name) == "EKS"
	some e in flatten_list(name, "Properties.ComputeEnvironmentOrder")
	ce := _pf_batch_oget(e.value, "ComputeEnvironment")
	cel := _pf_batch_ref(ce)
	p := _pf_batch_props(cel)
	not _pf_batch_ohas(p, "EksConfiguration")
}
