package cdk_preflight

import rego.v1

# Getting started: 'The password cannot include the word "admin."' スキーマの Pattern は
# 長さと文字種しか見ない。Windows の複雑さ規則（アカウント名を含めない）なので大文字小文字は区別しない。
# 動的参照（{{resolve:secretsmanager:...}}）は中身が見えないので黙る（参照名に admin が入っていても鳴らさない）。
violation contains make_diag_full("pf-ds-msad-password-no-admin", "ERROR", name,
	"Properties.Password",
	"Password contains the word 'admin'; the AWS Managed Microsoft AD Admin password cannot include it",
	"Choose a password that does not contain 'admin' (in any letter case)",
	"https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_getting_started.html") if {
	some name in resources_of_type("AWS::DirectoryService::MicrosoftAD")
	pw := resolve(name, "Properties.Password")
	is_string(pw)
	not contains(pw, "{{resolve:")
	contains(lower(pw), "admin")
}
