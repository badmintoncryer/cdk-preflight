package cdk_preflight

import rego.v1

# LogDestinationType is optional and defaults to cloud-watch-logs, so an absent
# type takes the cloud-watch-logs branch (measured: the same error fires).
_pf_ec2fld_type(name) := t if {
	t := resolve(name, "Properties.LogDestinationType")
	is_string(t)
}

_pf_ec2fld_type(name) := "cloud-watch-logs" if _pf_ec2fl_absent(name, "LogDestinationType")

violation contains make_diag_full("pf-ec2-flow-log-destination-config", "ERROR", name,
	"Properties.LogDestination",
	"A flow log with LogDestinationType s3 needs LogDestination (\"LogDestination can't be empty if LogGroupName is not provided.\")",
	"Set LogDestination to the target bucket ARN",
	_pf_ec2fl_url) if {
	some name in resources_of_type("AWS::EC2::FlowLog")
	_pf_ec2fld_type(name) == "s3"
	_pf_ec2fl_absent(name, "LogDestination")
}

violation contains make_diag_full("pf-ec2-flow-log-destination-config", "ERROR", name,
	"Properties.DeliverLogsPermissionArn",
	"A flow log delivering to CloudWatch Logs needs DeliverLogsPermissionArn (\"DeliverLogsPermissionArn can't be empty if LogDestinationType is cloud-watch-logs.\")",
	"Set DeliverLogsPermissionArn to a role the flow log service can assume",
	_pf_ec2fl_url) if {
	some name in resources_of_type("AWS::EC2::FlowLog")
	_pf_ec2fld_type(name) == "cloud-watch-logs"
	_pf_ec2fl_absent(name, "DeliverLogsPermissionArn")
}
