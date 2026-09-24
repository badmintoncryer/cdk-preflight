package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-backup-framework-name-charset", "ERROR", name,
	"Properties.FrameworkName",
	sprintf("FrameworkName %v must start with a letter and contain only letters, digits and underscores (hyphens are rejected)", [n]),
	"Rename the framework without hyphens, e.g. my_framework (CDK default names contain hyphens, so pass an explicit frameworkName)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-backup-framework.html") if {
	some name in resources_of_type("AWS::Backup::Framework")
	n := _pf_bklib_str(_pf_bklib_props(name), "FrameworkName")
	not regex.match(`^[A-Za-z][A-Za-z0-9_]*$`, n)
}
