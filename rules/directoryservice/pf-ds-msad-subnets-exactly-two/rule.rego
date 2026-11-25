package cdk_preflight

import rego.v1

# DirectoryVpcSettings: 'The two subnets must be in different Availability Zones. AWS Directory Service creates
# a directory server and a DNS server in each of these subnets.' 1 本でも 3 本でも拒否される。
# リスト丸ごとの Ref（List<Subnet::Id> パラメータ）と Fn::If を含むリストは個数が分からないので黙る。

violation contains make_diag_full("pf-ds-msad-subnets-exactly-two", "ERROR", name,
	"Properties.VpcSettings.SubnetIds",
	"VpcSettings.SubnetIds must list exactly two subnets for AWS Managed Microsoft AD",
	"List exactly two subnets, in different Availability Zones",
	"https://docs.aws.amazon.com/directoryservice/latest/devguide/API_DirectoryVpcSettings.html") if {
	some name in resources_of_type("AWS::DirectoryService::MicrosoftAD")
	raw := _pf_ll_raw(name, "Properties.VpcSettings.SubnetIds")
	is_array(raw)
	_pf_countable_list(name, "Properties.VpcSettings.SubnetIds")
	n := count(raw)
	n > 0
	n != 2
}
