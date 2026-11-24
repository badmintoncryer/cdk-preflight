package cdk_preflight

import rego.v1

# CFn スキーマの pattern ^[^\\/:*?"<>|.]+[^\\/:*?"<>|]*$ は先頭のピリオドしか禁じない。
# Simple AD で NetBIOS 名にピリオドを入れて作成が失敗した事例（DevelopersIO）から、MicrosoftAD でも確かめる。

violation contains make_diag_full("pf-ds-msad-shortname-no-period", "ERROR", name,
	"Properties.ShortName",
	"ShortName contains a period; a NetBIOS domain name cannot contain '.'",
	"Remove the period from ShortName (for example CORP instead of CORP.X)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-directoryservice-microsoftad.html") if {
	some name in resources_of_type("AWS::DirectoryService::MicrosoftAD")
	s := resolve(name, "Properties.ShortName")
	is_string(s)
	contains(s, ".")
}
