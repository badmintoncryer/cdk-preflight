package cdk_preflight

import rego.v1

_pf_asgzs_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

_pf_asgzs_skip(name) if resolve(name, "Properties.SkipZonalShiftValidation") == true

_pf_asgzs_crosszone_off(tg) if {
	some a in _pf_aslib_arr(tg, ["TargetGroupAttributes"])
	is_object(a)
	object.get(a, "Key", "") == "load_balancing.cross_zone.enabled"
	object.get(a, "Value", "") == "false"
}

violation contains make_diag_full("pf-asg-zonalshift-cross-zone-disabled-requires-skip-validation", "ERROR", name,
	sprintf("Properties.TargetGroupARNs.%d", [i]),
	sprintf("zonal shift is enabled but target group %s has cross-zone load balancing turned off, so traffic cannot leave an impaired zone; the group create fails with \"The use of a cross-zone disabled load balancer with zonal shift enabled for an Auto Scaling group is not supported\"", [tg]),
	"Enable load_balancing.cross_zone.enabled on the target group, or set SkipZonalShiftValidation", _pf_asgzs_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	resolve(name, "Properties.AvailabilityZoneImpairmentPolicy.ZonalShiftEnabled") == true
	not _pf_asgzs_skip(name)
	some i, _ in _pf_aslib_arr(name, ["TargetGroupARNs"])
	tg := resolve(name, sprintf("Properties.TargetGroupARNs.%d", [i]))
	tg in resources_of_type("AWS::ElasticLoadBalancingV2::TargetGroup")
	_pf_asgzs_crosszone_off(tg)
}
