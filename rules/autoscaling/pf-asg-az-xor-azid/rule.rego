package cdk_preflight

import rego.v1

_pf_asgazx_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-az-xor-azid", "ERROR", name,
	"Properties.AvailabilityZoneIds",
	"the group sets both AvailabilityZones and AvailabilityZoneIds; the group create fails with \"AvailabilityZones and AvailabilityZoneIds can't be used together\"",
	"Keep AvailabilityZones or AvailabilityZoneIds, not both", _pf_asgazx_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	not _pf_aslib_absent(name, "AvailabilityZones")
	not _pf_aslib_absent(name, "AvailabilityZoneIds")
}
