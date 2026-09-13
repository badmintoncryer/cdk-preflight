package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-artifacts-encryption-disabled-s3-only", "ERROR", name,
	"Properties.Artifacts.EncryptionDisabled",
	sprintf("EncryptionDisabled is set on %s artifacts; CreateProject fails with \"Invalid artifacts: artifact type %s should have null encryptionDisabled\"", [t, t]),
	"Drop EncryptionDisabled, or publish the artifacts to S3",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-artifacts.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	a := _pf_codebuildlib_artifacts(name)
	_pf_codebuildlib_true(object.get(a, "EncryptionDisabled", null))
	t := _pf_codebuildlib_str(a, "Type")
	t != "S3"
}
