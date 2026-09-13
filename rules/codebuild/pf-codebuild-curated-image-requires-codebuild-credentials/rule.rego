package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-curated-image-requires-codebuild-credentials", "ERROR", name,
	"Properties.Environment.ImagePullCredentialsType",
	sprintf("Image %s is a CodeBuild curated image but ImagePullCredentialsType is SERVICE_ROLE; CreateProject fails with \"Invalid input: cannot use a CodeBuild curated image with imagePullCredentialsType SERVICE_ROLE\"", [img]),
	"Use ImagePullCredentialsType CODEBUILD for a curated image",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-environment.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	e := _pf_codebuildlib_env(name)
	_pf_codebuildlib_str(e, "ImagePullCredentialsType") == "SERVICE_ROLE"
	img := _pf_codebuildlib_str(e, "Image")
	startswith(img, "aws/codebuild/")
}
