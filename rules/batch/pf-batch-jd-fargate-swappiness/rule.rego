package cdk_preflight

import rego.v1

# The survey probe carried MaxSwap as well and came back naming maxSwap, so
# the fail template sets Swappiness on its own for the bench run.
violation contains make_diag_full("pf-batch-jd-fargate-swappiness", "ERROR", name,
	"Properties.ContainerProperties.LinuxParameters.Swappiness",
	"a Fargate job definition sets LinuxParameters.Swappiness (\"linuxParameter.swappiness is not allowed for Fargate.\")",
	"Remove Swappiness, or run the job on EC2",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_LinuxParameters.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_fargate(name)
	_pf_batch_ohas(_pf_batch_lp(name), "Swappiness")
}
