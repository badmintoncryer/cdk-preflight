package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-fgac-requires-master-user", "ERROR", name,
	"Properties.AdvancedSecurityOptions.MasterUserOptions.MasterUserARN",
	"fine-grained access control is on with the internal user database off, but no MasterUserARN is given; CreateDomain answers \"If you don't enable the internal user database, you must provide a master user ARN.\"",
	"Set MasterUserOptions.MasterUserARN to an IAM principal, or turn InternalUserDatabaseEnabled on with a name and password",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-masteruseroptions.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "AdvancedSecurityOptions", "Enabled")
	not _pf_os_on(name, "AdvancedSecurityOptions", "InternalUserDatabaseEnabled")
	not _pf_os_has3(name, "AdvancedSecurityOptions", "MasterUserOptions", "MasterUserARN")
}
