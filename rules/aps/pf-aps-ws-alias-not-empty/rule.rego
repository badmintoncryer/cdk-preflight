package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aps-ws-alias-not-empty", "ERROR", name,
	"Properties.Alias",
	"Alias is present but empty; the Workspace handler fails with \"InvalidParameter: 1 validation error(s) found. minimum field size of 1, CreateWorkspaceInput.Alias.\"",
	"Give the workspace a non-empty alias, or leave Alias out altogether",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-aps-workspace.html") if {
	some name in resources_of_type("AWS::APS::Workspace")
	a := _pf_aps_str(name, "Properties.Alias")
	a == ""
}
