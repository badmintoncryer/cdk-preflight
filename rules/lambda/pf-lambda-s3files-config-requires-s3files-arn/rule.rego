package cdk_preflight

import rego.v1

# An EFS target: a literal elasticfilesystem ARN, or a Ref / GetAtt to an
# in-template EFS access point.
_pf_lmbs3f_efs(v) if {
	is_string(v)
	contains(v, ":elasticfilesystem:")
}

_pf_lmbs3f_efs(v) if {
	is_string(v)
	v in resources_of_type("AWS::EFS::AccessPoint")
}

_pf_lmbs3f_efs(v) if {
	is_object(v)
	t := object.get(v, "__ref", null)
	is_string(t)
	t in resources_of_type("AWS::EFS::AccessPoint")
}

violation contains make_diag_full("pf-lambda-s3files-config-requires-s3files-arn", "ERROR", name,
	sprintf("Properties.FileSystemConfigs.%d.S3FilesConfig", [c.index]),
	"S3FilesConfig is set on an EFS access point; CreateFunction fails with \"S3FilesConfig can only be specified for S3 Files file systems.\"",
	"Remove S3FilesConfig for EFS mounts, or point Arn at an S3 Files access point",
	"https://docs.aws.amazon.com/lambda/latest/api/API_FileSystemConfig.html") if {
	some name in resources_of_type("AWS::Lambda::Function")
	some c in flatten_list(name, "Properties.FileSystemConfigs")
	is_object(c.value)
	object.get(c.value, "S3FilesConfig", "__pf_absent") != "__pf_absent"
	arn := resolve(name, sprintf("Properties.FileSystemConfigs.%d.Arn", [c.index]))
	_pf_lmbs3f_efs(arn)
}
