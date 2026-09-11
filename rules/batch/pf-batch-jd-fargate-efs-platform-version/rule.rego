package cdk_preflight

import rego.v1

# Only the released pre-1.4.0 versions are listed, so a future version string
# never turns into a false positive.
violation contains make_diag_full("pf-batch-jd-fargate-efs-platform-version", "ERROR", name,
	"Properties.ContainerProperties.FargatePlatformConfiguration.PlatformVersion",
	sprintf("an EFS volume runs on platform version %v (\"EFS is supported for Fargate platform versions 1.4.0 or later, provided %v\")", [pv, pv]),
	"Use platform version 1.4.0 or LATEST",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_Volume.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_fargate(name)
	some v in _pf_batch_volumes(name)
	_pf_batch_efs(v)
	pv := _pf_batch_cpget(name, "FargatePlatformConfiguration").PlatformVersion
	pv in {"1.0.0", "1.1.0", "1.2.0", "1.3.0"}
}
