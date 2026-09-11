package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-fargate-volume-host-source-path", "ERROR", name,
	"Properties.ContainerProperties.Volumes",
	sprintf("a Fargate job definition sets Host.SourcePath on volume %v (\"host.sourcePath should not be set for volumes in Fargate.\")", [object.get(v.value, "Name", v.index)]),
	"Drop SourcePath, or run the job on EC2",
	"https://docs.aws.amazon.com/batch/latest/userguide/fargate-job-definitions.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_fargate(name)
	some v in _pf_batch_volumes(name)
	_pf_batch_ohas(_pf_batch_oget(v.value, "Host"), "SourcePath")
}
