package cdk_preflight

import rego.v1

_pf_ec2pidx_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-instance.html"

violation contains make_diag_full("pf-ec2-eni-public-ip-device-index", "ERROR", name,
	sprintf("Properties.NetworkInterfaces.%d.AssociatePublicIpAddress", [n.index]),
	sprintf("AssociatePublicIpAddress is set on device index %v; only index 0 accepts it (\"The associatePublicIPAddress parameter can only be specified for the network interface with DeviceIndex 0\")", [idx]),
	"Set AssociatePublicIpAddress on the device index 0 interface only",
	_pf_ec2pidx_url) if {
	some name in resources_of_type("AWS::EC2::Instance")
	some n in flatten_list(name, "Properties.NetworkInterfaces")
	coerce_to_bool(object.get(n.value, "AssociatePublicIpAddress", false)) == true
	idx := to_number(object.get(n.value, "DeviceIndex", 0))
	idx != 0
}
