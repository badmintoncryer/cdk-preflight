package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-s3files-requires-job-role", "ERROR", name,
	"Properties.ContainerProperties.JobRoleArn",
	sprintf("volume %v mounts an S3 Files file system but the job definition has no JobRoleArn (\"A jobRoleArn/taskRoleArn is required when using s3filesVolumeConfiguration.\")", [object.get(v.value, "Name", v.index)]),
	"Set ContainerProperties.JobRoleArn",
	"https://docs.aws.amazon.com/batch/latest/userguide/s3files-volumes.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some v in _pf_batch_volumes(name)
	_pf_batch_ohas(v.value, "S3FilesVolumeConfiguration")
	not _pf_batch_cphas(name, "JobRoleArn")
}
