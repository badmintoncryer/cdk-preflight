package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jq-ce-mix-fargate-ec2", "ERROR", name,
	"Properties.ComputeEnvironmentOrder",
	sprintf("the queue attaches both %v compute environments (\"Fargate and EC2 compute environments can not be mixed.\")", [concat(" and ", sort(kinds))]),
	"Give Fargate and EC2 capacity their own job queues",
	"https://docs.aws.amazon.com/batch/latest/userguide/job_queues.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	kinds := {k | some e in flatten_list(name, "Properties.ComputeEnvironmentOrder"); cel := _pf_batch_ref(_pf_batch_oget(e.value, "ComputeEnvironment")); k := _pf_batch_ce_kind(cel)}
	count(kinds) > 1
}
