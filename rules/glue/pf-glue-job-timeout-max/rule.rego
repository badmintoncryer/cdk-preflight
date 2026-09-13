package cdk_preflight

import rego.v1

# The bundled registry schema carries no maximum for Timeout.
violation contains make_diag_full("pf-glue-job-timeout-max", "ERROR", name,
	"Properties.Timeout",
	sprintf("Timeout %v minutes; CreateJob caps a job at 10080 minutes (7 days)", [t]),
	"Set Timeout to 10080 or less",
	"https://docs.aws.amazon.com/glue/latest/dg/aws-glue-api-jobs-job.html") if {
	some name in resources_of_type("AWS::Glue::Job")
	t := _pf_gluelib_num(name, "Properties.Timeout")
	t > 10080
}
