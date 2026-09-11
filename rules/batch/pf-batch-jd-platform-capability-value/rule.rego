package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-platform-capability-value", "ERROR", name,
	"Properties.PlatformCapabilities",
	sprintf("%v is not a platform capability (\"Capability %v is not valid. Valid capabilities: [FARGATE, EC2, MANAGED_INSTANCES]\")", [c, c]),
	"Use EC2, FARGATE or MANAGED_INSTANCES",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some pc in flatten_list(name, "Properties.PlatformCapabilities")
	c := pc.value
	_pf_batch_lit(c)
	not c in {"EC2", "FARGATE", "MANAGED_INSTANCES"}
}
