package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-jobtemplate-abort-threshold", "ERROR", name,
	sprintf("Properties.AbortConfig.CriteriaList[%d].ThresholdPercentage", [c.index]),
	sprintf("ThresholdPercentage %v aborts nothing; CreateJobTemplate answers \"ThresholdPercentage value %v for AbortCriteria must have value greater than 0\"", [t, t]),
	"Set ThresholdPercentage above 0",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_AbortCriteria.html") if {
	some name in resources_of_type("AWS::IoT::JobTemplate")
	some c in flatten_list(name, "Properties.AbortConfig.CriteriaList")
	t := object.get(c.value, "ThresholdPercentage", null)
	is_number(t)
	t <= 0
}
