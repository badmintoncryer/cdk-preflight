package cdk_preflight

import rego.v1

_pf_ec2icmp_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-securitygroupingress.html"

# For ICMP, FromPort carries the type and ToPort the code; both run -1..255,
# which is far narrower than the 0..65535 the schema allows for ports.
# resources_of_type は配列を返すので集合演算ができない。2 節の部分集合で束ねる
_pf_ec2icmp_names contains n if some n in resources_of_type("AWS::EC2::SecurityGroupIngress")

_pf_ec2icmp_names contains n if some n in resources_of_type("AWS::EC2::SecurityGroupEgress")

_pf_ec2icmp_icmp(name) if lower(resolve(name, "Properties.IpProtocol")) in {"icmp", "icmpv6", "58"}

_pf_ec2icmp_icmp(name) if to_number(resolve(name, "Properties.IpProtocol")) == 1

_pf_ec2icmp_bad(name, key) := v if {
	v := to_number(resolve(name, sprintf("Properties.%s", [key])))
	v > 255
}

_pf_ec2icmp_bad(name, key) := v if {
	v := to_number(resolve(name, sprintf("Properties.%s", [key])))
	v < -1
}

violation contains make_diag_full("pf-ec2-sg-icmp-type-code", "ERROR", name,
	sprintf("Properties.%s", [key]),
	sprintf("For ICMP, %s carries the %s and must be -1..255; %v is out of range (\"ICMP %s (%v) out of range\")", [key, part, v, part, v]),
	"Use an ICMP type/code in -1..255, or -1 for all",
	_pf_ec2icmp_url) if {
	some name in _pf_ec2icmp_names
	_pf_ec2icmp_icmp(name)
	some [key, part] in [["FromPort", "type"], ["ToPort", "code"]]
	v := _pf_ec2icmp_bad(name, key)
}
