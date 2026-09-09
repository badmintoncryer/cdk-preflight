package cdk_preflight

import rego.v1

_pf_asgimp_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-instance-maintenance-policy-range-diff", "ERROR", name,
	"Properties.InstanceMaintenancePolicy.MaxHealthyPercentage",
	sprintf("MaxHealthyPercentage %v minus MinHealthyPercentage %v is %v; the spread may not exceed 100 and the group create fails with \"The difference between MaxHealthyPercentage and MinHealthyPercentage must be less than or equal to 100\"", [mx, mn, mx - mn]),
	"Narrow the two percentages to within 100 points of each other", _pf_asgimp_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	mn := _pf_aslib_num(name, "Properties.InstanceMaintenancePolicy.MinHealthyPercentage")
	mx := _pf_aslib_num(name, "Properties.InstanceMaintenancePolicy.MaxHealthyPercentage")
	mx - mn > 100
}
