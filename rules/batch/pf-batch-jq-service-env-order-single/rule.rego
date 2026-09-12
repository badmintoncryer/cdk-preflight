package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jq-service-env-order-single", "ERROR", name,
	"Properties.ServiceEnvironmentOrder",
	sprintf("the job queue attaches %v service environments (\"Job queue can only have 1 service environment.\")", [n]),
	"Attach exactly one service environment",
	"https://docs.aws.amazon.com/batch/latest/userguide/what-are-service-environments.html") if {
	some name in resources_of_type("AWS::Batch::JobQueue")
	n := count(flatten_list(name, "Properties.ServiceEnvironmentOrder"))
	n > 1
}
