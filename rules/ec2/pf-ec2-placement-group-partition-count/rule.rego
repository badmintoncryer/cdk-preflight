package cdk_preflight

import rego.v1

_pf_ec2pgp_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-placementgroup.html"

violation contains make_diag_full("pf-ec2-placement-group-partition-count", "ERROR", name,
	"Properties.PartitionCount",
	sprintf("PartitionCount is set with the '%s' strategy (\"partition-count is only available with the 'partition' strategy.\")", [s]),
	"Set Strategy to partition, or drop PartitionCount",
	_pf_ec2pgp_url) if {
	some name in resources_of_type("AWS::EC2::PlacementGroup")
	not _pf_ec2lib_absent(name, "PartitionCount")
	s := resolve(name, "Properties.Strategy")
	is_string(s)
	s != "partition"
}
