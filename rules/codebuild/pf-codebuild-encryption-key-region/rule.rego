package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-encryption-key-region", "ERROR", name,
	"Properties.EncryptionKey",
	sprintf("EncryptionKey is a KMS key in %s but the project deploys to %s; CreateProject fails with \"Invalid encryption key: region does not match current region\"", [r, data.cdk_preflight.deploy_region]),
	"Reference a KMS key in the deployment Region",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-project.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	v := object.get(_pf_codebuildlib_props(name), "EncryptionKey", null)
	_pf_codebuildlib_arn_service(v) == "kms"
	r := _pf_codebuildlib_region_mismatch(v)
}
