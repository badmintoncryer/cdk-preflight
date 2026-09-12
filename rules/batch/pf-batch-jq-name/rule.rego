package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jq-name", "ERROR", name,
	"Properties.JobQueueName",
	sprintf("JobQueueName %v is rejected by the service: letters, numbers, hyphen and underscore, at most 128 characters (\"Job Queue name should match a valid pattern.\")", [v]),
	"Rename the job queue to satisfy letters, numbers, hyphen and underscore, at most 128 characters",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateJobQueue.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	v := resolve(name, "Properties.JobQueueName")
	is_string(v)
	not regex.match(`^[a-zA-Z0-9_-]{1,128}$`, v)
}
