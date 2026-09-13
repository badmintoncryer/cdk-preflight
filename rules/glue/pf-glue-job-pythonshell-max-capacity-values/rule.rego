package cdk_preflight

import rego.v1

# Two separate CreateJob checks sit behind this: values above 1.0 and
# fractional values other than 0.0625. 0 is accepted (the service reads it
# as unset), so it stays out of the violation set.
violation contains make_diag_full("pf-glue-job-pythonshell-max-capacity-values", "ERROR", name,
	"Properties.MaxCapacity",
	sprintf("MaxCapacity %v on a pythonshell job; only 0.0625 or 1 DPU are accepted", [mc]),
	"Set MaxCapacity to 0.0625 or 1",
	"https://docs.aws.amazon.com/glue/latest/dg/add-job-python.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	_pf_gluelib_command_name(name) == "pythonshell"
	mc := _pf_gluelib_num(name, "Properties.MaxCapacity")
	not mc in {0, 0.0625, 1}
}
