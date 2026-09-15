package cdk_preflight

import rego.v1

# Measured deny-list rather than "anything but S3": these are the two types the
# service names, and the message quotes the type back.
_pf_cbsas3_denied := {"CODEPIPELINE": true, "NO_ARTIFACTS": true}

violation contains make_diag_full("pf-codebuild-secondary-artifacts-s3-only", "ERROR", name,
	sprintf("Properties.SecondaryArtifacts[%d].Type", [item.index]),
	sprintf("A secondary artifact has Type %s; CreateProject fails with \"Invalid input: artifactType %s is not allowed for secondaryArtifacts\"", [t, t]),
	"Publish secondary artifacts to S3, or drop the entry",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-artifacts.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	some item in flatten_list(name, "Properties.SecondaryArtifacts")
	t := item.value.Type
	_pf_cbsas3_denied[t]
}
