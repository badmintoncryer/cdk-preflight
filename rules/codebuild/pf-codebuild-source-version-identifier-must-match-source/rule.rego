package cdk_preflight

import rego.v1

# Only SecondarySources count: pointing the entry at the primary Source's own
# SourceIdentifier is rejected the same way.
violation contains make_diag_full("pf-codebuild-source-version-identifier-must-match-source", "ERROR", name,
	sprintf("Properties.SecondarySourceVersions[%d].SourceIdentifier", [item.index]),
	sprintf("SecondarySourceVersions names %s, which no SecondarySources entry declares; CreateProject fails with \"Invalid input: secondary source identifier does not exist\"", [id]),
	"Point the entry at a SecondarySources SourceIdentifier, or drop it",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-projectsourceversion.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	some item in flatten_list(name, "Properties.SecondarySourceVersions")
	id := item.value.SourceIdentifier
	is_string(id)
	declared := {i |
		some s in flatten_list(name, "Properties.SecondarySources")
		i := s.value.SourceIdentifier
	}
	not declared[id]
}
