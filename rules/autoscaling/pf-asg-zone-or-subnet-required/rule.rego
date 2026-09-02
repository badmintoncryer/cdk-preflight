package cdk_preflight

import rego.v1

# Placement must come from somewhere. Absence is proven against the
# preprocessed document (see AGENTS.md).
_pf_asgzsr_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-asg-zone-or-subnet-required", "ERROR", name,
	"Properties.VPCZoneIdentifier",
	"Neither AvailabilityZones, AvailabilityZoneIds, nor VPCZoneIdentifier is set; the group create fails with \"You must specify 1 of either AvailabilityZones, AvailabilityZoneIds, or Subnets\"",
	"Set VPCZoneIdentifier with the target subnets (or AvailabilityZones)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-autoscaling-autoscalinggroup.html") if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	_pf_asgzsr_absent(name, "AvailabilityZones")
	_pf_asgzsr_absent(name, "AvailabilityZoneIds")
	_pf_asgzsr_absent(name, "VPCZoneIdentifier")
}
