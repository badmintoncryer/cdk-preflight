package cdk_preflight

import rego.v1

# Runtime is not ignored when it does not apply — CreateJob rejects it.
violation contains make_diag_full("pf-glue-job-runtime-ray-only", "ERROR", name,
	"Properties.Command.Runtime",
	sprintf("Command.Runtime %v on a %v job; Runtime names the Ray environment and is rejected for every other command", [rt, cmd]),
	"Remove Command.Runtime",
	"https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-jobs-job.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	rt := _pf_gluelib_str(name, "Properties.Command.Runtime")
	cmd := _pf_gluelib_command_name(name)
	cmd != "glueray"
}
