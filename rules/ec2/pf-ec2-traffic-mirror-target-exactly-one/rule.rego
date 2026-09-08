package cdk_preflight

import rego.v1

_pf_ec2tmt_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-trafficmirrortarget.html"

_pf_ec2tmt_keys := ["NetworkInterfaceId", "NetworkLoadBalancerArn", "GatewayLoadBalancerEndpointId"]

_pf_ec2tmt_set(name) := [k | some k in _pf_ec2tmt_keys; not _pf_ec2lib_absent(name, k)]

violation contains make_diag_full("pf-ec2-traffic-mirror-target-exactly-one", "ERROR", name,
	"Properties",
	sprintf("A traffic mirror target names %v destinations (\"Request should contain exactly one of NetworkInterfaceId or NetworkLoadBalancerArn or GatewayLoadBalancerEndpointId\")", [count(ks)]),
	"Set exactly one of NetworkInterfaceId, NetworkLoadBalancerArn or GatewayLoadBalancerEndpointId",
	_pf_ec2tmt_url) if {
	some name in resources_of_type("AWS::EC2::TrafficMirrorTarget")
	ks := _pf_ec2tmt_set(name)
	count(ks) != 1
}
