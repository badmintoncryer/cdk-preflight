package cdk_preflight

import rego.v1

_pf_asgvam_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-vpczone-az-mismatch", "ERROR", name,
	sprintf("Properties.VPCZoneIdentifier.%d", [i]),
	sprintf("subnet %s sits in %s, which AvailabilityZones does not list; the group create fails with \"The availability zones of the specified subnets and the Auto Scaling group do not match\"", [sub, az]),
	"Drop AvailabilityZones and let the subnets decide, or list the subnets' zones", _pf_asgvam_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	azs := _pf_aslib_arr(name, ["AvailabilityZones"])
	azset := {z | some z in azs; is_string(z)}
	count(azset) > 0
	some i, _ in _pf_aslib_arr(name, ["VPCZoneIdentifier"])
	sub := resolve(name, sprintf("Properties.VPCZoneIdentifier.%d", [i]))
	sub in resources_of_type("AWS::EC2::Subnet")
	az := resolve(sub, "Properties.AvailabilityZone")
	_pf_aslib_lit(az)
	not az in azset
}
