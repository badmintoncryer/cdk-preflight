package cdk_preflight

import rego.v1

_pf_ec2flf_fields := {"version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol", "packets", "bytes", "start", "end", "action", "log-status", "vpc-id", "subnet-id", "instance-id", "tcp-flags", "type", "pkt-srcaddr", "pkt-dstaddr", "region", "az-id", "sublocation-type", "sublocation-id", "pkt-src-aws-service", "pkt-dst-aws-service", "flow-direction", "traffic-path", "ecs-cluster-arn", "ecs-cluster-name", "ecs-container-instance-arn", "ecs-container-instance-id", "ecs-container-id", "ecs-second-container-id", "ecs-service-name", "ecs-task-definition-arn", "ecs-task-arn", "ecs-task-id", "reject-reason"}

_pf_ec2flf_unknown(name) := f if {
	s := resolve(name, "Properties.LogFormat")
	is_string(s)
	some tok in regex.find_n(`\$\{[^}]*\}`, s, -1)
	f := trim_suffix(trim_prefix(tok, "${"), "}")
	not f in _pf_ec2flf_fields
}

violation contains make_diag_full("pf-ec2-flow-log-format-fields", "ERROR", name,
	"Properties.LogFormat",
	sprintf("LogFormat names the field '%s', which flow logs do not provide (\"Unknown fields provided\")", [f]),
	"Use only the documented ${field} names; check the log record fields table",
	_pf_ec2fl_url) if {
	some name in resources_of_type("AWS::EC2::FlowLog")
	f := _pf_ec2flf_unknown(name)
}
