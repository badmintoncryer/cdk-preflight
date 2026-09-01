package cdk_preflight

import rego.v1

_pf_sg_fix := "Use a port between 0 and 65535 with FromPort <= ToPort"

_pf_sg_url := "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html"

_pf_port_out(n) if n < 0

_pf_port_out(n) if n > 65535

_pf_tcp_udp(p) if p in {"tcp", "udp", "6", "17", 6, 17}

violation contains make_diag_full("pf-ec2-sg-port-range", "ERROR", name,
	sprintf("Properties.%s.%d.%s", [dir, item.index, pname]),
	sprintf("%s %v is outside the valid TCP/UDP port range 0-65535", [pname, n]),
	_pf_sg_fix, _pf_sg_url) if {
	some name in resources_of_type("AWS::EC2::SecurityGroup")
	some dir in {"SecurityGroupIngress", "SecurityGroupEgress"}
	some item in flatten_list(name, sprintf("Properties.%s", [dir]))
	entry := item.value
	is_object(entry)
	_pf_tcp_udp(object.get(entry, "IpProtocol", null))
	some pname in {"FromPort", "ToPort"}
	n := to_number(object.get(entry, pname, null))
	_pf_port_out(n)
}

violation contains make_diag_full("pf-ec2-sg-port-range", "ERROR", name,
	sprintf("Properties.%s.%d.FromPort", [dir, item.index]),
	sprintf("FromPort (%v) must be less than or equal to ToPort (%v)", [f, t]),
	_pf_sg_fix, _pf_sg_url) if {
	some name in resources_of_type("AWS::EC2::SecurityGroup")
	some dir in {"SecurityGroupIngress", "SecurityGroupEgress"}
	some item in flatten_list(name, sprintf("Properties.%s", [dir]))
	entry := item.value
	is_object(entry)
	_pf_tcp_udp(object.get(entry, "IpProtocol", null))
	f := to_number(object.get(entry, "FromPort", null))
	t := to_number(object.get(entry, "ToPort", null))
	f >= 0
	t <= 65535
	f > t
}

violation contains make_diag_full("pf-ec2-sg-port-range", "ERROR", name,
	sprintf("Properties.%s", [pname]),
	sprintf("%s %v is outside the valid TCP/UDP port range 0-65535", [pname, n]),
	_pf_sg_fix, _pf_sg_url) if {
	some rtype in {"AWS::EC2::SecurityGroupIngress", "AWS::EC2::SecurityGroupEgress"}
	some name in resources_of_type(rtype)
	_pf_tcp_udp(resolve(name, "Properties.IpProtocol"))
	some pname in {"FromPort", "ToPort"}
	n := to_number(resolve(name, sprintf("Properties.%s", [pname])))
	_pf_port_out(n)
}

violation contains make_diag_full("pf-ec2-sg-port-range", "ERROR", name,
	"Properties.FromPort",
	sprintf("FromPort (%v) must be less than or equal to ToPort (%v)", [f, t]),
	_pf_sg_fix, _pf_sg_url) if {
	some rtype in {"AWS::EC2::SecurityGroupIngress", "AWS::EC2::SecurityGroupEgress"}
	some name in resources_of_type(rtype)
	_pf_tcp_udp(resolve(name, "Properties.IpProtocol"))
	f := to_number(resolve(name, "Properties.FromPort"))
	t := to_number(resolve(name, "Properties.ToPort"))
	f >= 0
	t <= 65535
	f > t
}
