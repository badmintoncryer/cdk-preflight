package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jq-ce-order-max", "ERROR", name,
	"Properties.ComputeEnvironmentOrder",
	sprintf("the job queue attaches %v compute environments (\"Only 3 environments are allowed in job queue request.\")", [n]),
	"Attach at most 3 compute environments",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateJobQueue.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	n := count(flatten_list(name, "Properties.ComputeEnvironmentOrder"))
	n > 3
}
