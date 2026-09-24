package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-fgac-internal-db-requires-name-password", "ERROR", name,
	"Properties.AdvancedSecurityOptions.MasterUserOptions",
	sprintf("the internal user database is enabled but %v is missing; CreateDomain answers \"You must provide a master username and password when the internal user database is enabled.\"", [k]),
	"Set both MasterUserName and MasterUserPassword under MasterUserOptions, or turn InternalUserDatabaseEnabled off and use MasterUserARN",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-masteruseroptions.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "AdvancedSecurityOptions", "InternalUserDatabaseEnabled")
	some k in ["MasterUserName", "MasterUserPassword"]
	not _pf_os_has3(name, "AdvancedSecurityOptions", "MasterUserOptions", k)
}
