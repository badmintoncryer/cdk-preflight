package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ec2-prefix-list-max-entries", "ERROR", name,
	"Properties.MaxEntries",
	sprintf("MaxEntries is %v but Entries has %v members (\"The number of entries cannot be greater than the maximum number of entries\")", [me, count(entries)]),
	"Raise MaxEntries to at least the number of entries",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-prefixlist.html") if {
	some name in resources_of_type("AWS::EC2::PrefixList")
	me := to_number(resolve(name, "Properties.MaxEntries"))
	entries := flatten_list(name, "Properties.Entries")
	count(entries) > me
}
