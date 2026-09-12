package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-mi-no-multinode", "ERROR", name,
	"Properties.PlatformCapabilities",
	"a MANAGED_INSTANCES job definition sets NodeProperties (\"MANAGED_INSTANCES does not support MNP jobs\")",
	"Drop NodeProperties, or use the EC2 platform capability",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_mi(name)
	_pf_batch_has(name, "NodeProperties")
}
