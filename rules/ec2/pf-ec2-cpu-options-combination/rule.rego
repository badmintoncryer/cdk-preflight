package cdk_preflight

import rego.v1

_pf_ec2cpu_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-instance.html"

# The accepted CoreCount / ThreadsPerCore pairs are per instance type, and the
# survey warned against extrapolating that table. These two bounds hold for
# every type measured: ThreadsPerCore is only ever 1 or 2, and CoreCount is at
# least 1. Anything outside them is rejected whatever the instance type is.
violation contains make_diag_full("pf-ec2-cpu-options-combination", "ERROR", name,
	"Properties.CpuOptions.ThreadsPerCore",
	sprintf("ThreadsPerCore %v is out of range; EC2 accepts 1 or 2 (\"A value of %v for ThreadsPerCore is not a valid value for the ... instance type\")", [t, t]),
	"Set ThreadsPerCore to 1 (SMT off) or 2",
	_pf_ec2cpu_url) if {
	some name in resources_of_type("AWS::EC2::Instance")
	t := to_number(resolve(name, "Properties.CpuOptions.ThreadsPerCore"))
	not t in {1, 2}
}

violation contains make_diag_full("pf-ec2-cpu-options-combination", "ERROR", name,
	"Properties.CpuOptions.CoreCount",
	sprintf("CoreCount %v is out of range; it must be at least 1", [c]),
	"Set CoreCount to a core count the instance type offers",
	_pf_ec2cpu_url) if {
	some name in resources_of_type("AWS::EC2::Instance")
	c := to_number(resolve(name, "Properties.CpuOptions.CoreCount"))
	c < 1
}
