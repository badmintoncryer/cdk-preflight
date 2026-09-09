package cdk_preflight

import rego.v1

_pf_asgirvm_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

_pf_asgirvm_ranges := ["VCpuCount", "MemoryMiB", "MemoryGiBPerVCpu", "NetworkBandwidthGbps", "NetworkInterfaceCount", "TotalLocalStorageGB", "BaselineEbsBandwidthMbps", "AcceleratorCount", "AcceleratorTotalMemoryMiB"]

violation contains make_diag_full("pf-asg-instance-requirements-vcpu-min-max", "ERROR", name,
	sprintf("Properties.MixedInstancesPolicy.LaunchTemplate.Overrides.%d.InstanceRequirements.%s", [i, k]),
	sprintf("%s has Min %v above Max %v; the group create fails with \"Invalid instance requirements. The Min value (%v) in %s must be less or equal to the Max value (%v)\"", [k, mn, mx, mn, k, mx]),
	sprintf("Set the %s Min at or below its Max", [k]), _pf_asgirvm_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	some i, o in _pf_aslib_overrides(name)
	is_object(o)
	ir := object.get(o, "InstanceRequirements", null)
	is_object(ir)
	some k in _pf_asgirvm_ranges
	r := object.get(ir, k, null)
	is_object(r)
	mn := object.get(r, "Min", null)
	mx := object.get(r, "Max", null)
	is_number(mn)
	is_number(mx)
	mn > mx
}
