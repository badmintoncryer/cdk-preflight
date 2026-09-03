package cdk_preflight

import rego.v1

_pf_ec2scv_url := "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html"

_pf_ec2scv_malformed(c) if {
	regex.match(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$`, c)
	to_number(split(c, "/")[1]) > 32
}

_pf_ec2scv_malformed(c) if {
	regex.match(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$`, c)
	some o in split(split(c, "/")[0], ".")
	to_number(o) > 255
}

violation contains make_diag_full("pf-ec2-sg-cidr-valid", "ERROR", name,
	sprintf("Properties.%s.%d.CidrIp", [dir, item.index]),
	sprintf("CidrIp '%s' is malformed (octets must be 0-255, prefix 0-32); EC2 rejects it with \"CIDR block %s is malformed\"", [c, c]),
	"Fix the CIDR notation",
	_pf_ec2scv_url) if {
	some name in resources_of_type("AWS::EC2::SecurityGroup")
	some dir in {"SecurityGroupIngress", "SecurityGroupEgress"}
	some item in flatten_list(name, sprintf("Properties.%s", [dir]))
	entry := item.value
	is_object(entry)
	c := object.get(entry, "CidrIp", null)
	is_string(c)
	_pf_ec2scv_malformed(c)
}

violation contains make_diag_full("pf-ec2-sg-cidr-valid", "ERROR", name,
	"Properties.CidrIp",
	sprintf("CidrIp '%s' is malformed (octets must be 0-255, prefix 0-32); EC2 rejects it with \"CIDR block %s is malformed\"", [c, c]),
	"Fix the CIDR notation",
	_pf_ec2scv_url) if {
	some rtype in {"AWS::EC2::SecurityGroupIngress", "AWS::EC2::SecurityGroupEgress"}
	some name in resources_of_type(rtype)
	c := resolve(name, "Properties.CidrIp")
	is_string(c)
	_pf_ec2scv_malformed(c)
}
