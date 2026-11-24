package cdk_preflight

import rego.v1

# ActiveDirectoryId（AWS Managed AD）と SelfManagedActiveDirectoryConfiguration は排他。

violation contains make_diag_full("pf-fsx-windows-ad-exclusive", "ERROR", name,
	"Properties.WindowsConfiguration.SelfManagedActiveDirectoryConfiguration",
	"WindowsConfiguration sets both ActiveDirectoryId and SelfManagedActiveDirectoryConfiguration; choose one",
	"Keep ActiveDirectoryId for AWS Managed Microsoft AD, or SelfManagedActiveDirectoryConfiguration for a self-managed AD",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-fsx-filesystem-windowsconfiguration.html") if {
	some name in resources_of_type("AWS::FSx::FileSystem")
	w := input.resources[name].properties.WindowsConfiguration
	is_object(w)
	"ActiveDirectoryId" in object.keys(w)
	"SelfManagedActiveDirectoryConfiguration" in object.keys(w)
}
