package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-platform-capabilities-single", "ERROR", name,
	"Properties.PlatformCapabilities",
	sprintf("PlatformCapabilities holds %v values (\"Exactly 1 capability must be provided.\")", [n]),
	"Keep a single capability",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	n := count(flatten_list(name, "Properties.PlatformCapabilities"))
	n > 1
}
