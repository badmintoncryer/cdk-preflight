package cdk_preflight

import rego.v1

# Only pythonshell takes a fractional allocation (0.0625). glueetl and
# gluestreaming reject anything with a decimal part, at any magnitude.
violation contains make_diag_full("pf-glue-job-max-capacity-fractional", "ERROR", name,
	"Properties.MaxCapacity",
	sprintf("MaxCapacity %v on a %v job; Spark jobs take whole DPUs only", [mc, cmd]),
	"Round MaxCapacity up to a whole number of DPUs",
	"https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-jobs-job.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	cmd := _pf_gluelib_command_name(name)
	cmd in {"glueetl", "gluestreaming"}
	mc := _pf_gluelib_num(name, "Properties.MaxCapacity")
	mc != floor(mc)
}
