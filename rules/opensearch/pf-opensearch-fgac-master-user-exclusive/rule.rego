package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-fgac-master-user-exclusive", "ERROR", name,
	"Properties.AdvancedSecurityOptions.MasterUserOptions",
	"MasterUserOptions carries both a MasterUserName and a MasterUserARN; CreateDomain answers \"You must provide either a master username or a master user ARN but not together.\"",
	"Keep MasterUserName/MasterUserPassword for the internal user database, or MasterUserARN for an IAM principal - not both",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-masteruseroptions.html") if {
	some name in _pf_os_domains
	_pf_os_has3(name, "AdvancedSecurityOptions", "MasterUserOptions", "MasterUserName")
	_pf_os_has3(name, "AdvancedSecurityOptions", "MasterUserOptions", "MasterUserARN")
}
