package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-fargate-platform-config-on-ec2", "ERROR", name,
	"Properties.ContainerProperties.FargatePlatformConfiguration",
	"an EC2 job definition sets FargatePlatformConfiguration (\"fargatePlatformConfiguration not applicable for EC2.\")",
	"Remove FargatePlatformConfiguration, or add PlatformCapabilities: [FARGATE]",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_FargatePlatformConfiguration.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_ec2(name)
	_pf_batch_cphas(name, "FargatePlatformConfiguration")
}
