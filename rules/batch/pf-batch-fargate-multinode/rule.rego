package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-fargate-multinode", "ERROR", name,
	"Properties.PlatformCapabilities",
	"Type multinode cannot run on Fargate (\"Fargate does not support MNP jobs\")",
	"Use EC2 platform capabilities for multi-node parallel jobs",
	"https://docs.aws.amazon.com/batch/latest/userguide/multi-node-parallel-jobs.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	resolve(name, "Properties.Type") == "multinode"
	some pc in flatten_list(name, "Properties.PlatformCapabilities")
	pc.value == "FARGATE"
}
