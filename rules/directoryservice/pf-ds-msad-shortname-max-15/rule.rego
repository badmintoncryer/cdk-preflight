package cdk_preflight

import rego.v1

# NetBIOS 名は 15 文字まで。CFn スキーマの ShortName の pattern は文字種しか見ず、長さの上限を持たない。

violation contains make_diag_full("pf-ds-msad-shortname-max-15", "ERROR", name,
	"Properties.ShortName",
	"ShortName is longer than 15 characters; a NetBIOS domain name can be at most 15 characters",
	"Use a ShortName of 15 characters or fewer",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-directoryservice-microsoftad.html") if {
	some name in resources_of_type("AWS::DirectoryService::MicrosoftAD")
	s := resolve(name, "Properties.ShortName")
	is_string(s)
	count(s) > 15
}
