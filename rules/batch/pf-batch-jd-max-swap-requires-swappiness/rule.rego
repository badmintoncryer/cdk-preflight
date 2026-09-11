package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-max-swap-requires-swappiness", "ERROR", name,
	"Properties.ContainerProperties.LinuxParameters.Swappiness",
	"MaxSwap is set without Swappiness (\"When container specified swap memory, swappiness value is required.\")",
	"Set LinuxParameters.Swappiness alongside MaxSwap",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	lp := _pf_batch_lp(name)
	_pf_batch_ohas(lp, "MaxSwap")
	not _pf_batch_ohas(lp, "Swappiness")
}
