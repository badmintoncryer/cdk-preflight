package cdk_preflight

import rego.v1

# FSx Windows guide: 'For Single-AZ 2 and all Multi-AZ file systems, the Active Directory fully qualified domain name
# (FQDN) cannot exceed 47 characters.' 自己管理 AD の DomainName か、同じテンプレートの MicrosoftAD の Name を見る。
# DeploymentType を書かない（既定 SINGLE_AZ_1）なら黙る。
_pf_fsxfq_fqdn(name) := d if {
	d := resolve(name, "Properties.WindowsConfiguration.SelfManagedActiveDirectoryConfiguration.DomainName")
	is_string(d)
}

_pf_fsxfq_fqdn(name) := d if {
	ref := resolve(name, "Properties.WindowsConfiguration.ActiveDirectoryId")
	is_string(ref)
	ref in resources_of_type("AWS::DirectoryService::MicrosoftAD")
	d := resolve(ref, "Properties.Name")
	is_string(d)
}

violation contains make_diag_full("pf-fsx-windows-ad-fqdn-max-47", "ERROR", name,
	"Properties.WindowsConfiguration",
	"The Active Directory FQDN is longer than 47 characters; Single-AZ 2 and Multi-AZ FSx for Windows file systems cannot join it",
	"Use a SINGLE_AZ_1 deployment, or a directory whose fully qualified domain name is 47 characters or fewer",
	"https://docs.aws.amazon.com/fsx/latest/WindowsGuide/fsx-aws-managed-ad.html") if {
	some name in resources_of_type("AWS::FSx::FileSystem")
	dt := resolve(name, "Properties.WindowsConfiguration.DeploymentType")
	dt in {"SINGLE_AZ_2", "MULTI_AZ_1"}
	fqdn := _pf_fsxfq_fqdn(name)
	count(fqdn) > 47
}
