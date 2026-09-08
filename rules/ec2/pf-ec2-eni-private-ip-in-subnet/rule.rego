package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ec2-eni-private-ip-in-subnet", "ERROR", name,
	"Properties.PrivateIpAddress",
	sprintf("PrivateIpAddress %s is outside subnet '%s' (%s); the create fails with \"Address does not fall within the subnet's address range\"", [ip, sref, cidr]),
	"Pick an address inside the subnet CIDR, or drop PrivateIpAddress and let EC2 assign one",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-networkinterface.html") if {
	some name in resources_of_type("AWS::EC2::NetworkInterface")
	ip := resolve(name, "Properties.PrivateIpAddress")
	is_string(ip)
	sref := resolve(name, "Properties.SubnetId")
	is_string(sref)
	sref in resources_of_type("AWS::EC2::Subnet")
	cidr := resolve(sref, "Properties.CidrBlock")
	is_string(cidr)
	not _pf_ec2lib_cidr_has_ip(cidr, ip)
}
