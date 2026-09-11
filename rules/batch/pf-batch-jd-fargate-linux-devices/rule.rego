package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-fargate-linux-devices", "ERROR", name,
	"Properties.ContainerProperties.LinuxParameters.Devices",
	"a Fargate job definition sets LinuxParameters.Devices (\"linuxParameter.devices is not allowed for Fargate.\")",
	"Remove Devices, or run the job on EC2",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_Device.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_fargate(name)
	_pf_batch_ohas(_pf_batch_lp(name), "Devices")
}
