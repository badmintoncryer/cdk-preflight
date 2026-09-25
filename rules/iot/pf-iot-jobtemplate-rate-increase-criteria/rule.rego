package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-jobtemplate-rate-increase-criteria", "ERROR", name,
	"Properties.JobExecutionsRolloutConfig.ExponentialRolloutRate.RateIncreaseCriteria",
	"RateIncreaseCriteria sets both NumberOfNotifiedThings and NumberOfSucceededThings; CreateJobTemplate answers \"Provide only one of NumberOfNotifiedThings or NumberOfSucceededThings when RateIncreaseCriteria is defined\"",
	"Keep the one criterion the rollout should ramp on",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_RateIncreaseCriteria.html") if {
	some name in resources_of_type("AWS::IoT::JobTemplate")
	ric := object.get(_pf_iotlib_props(name), ["JobExecutionsRolloutConfig", "ExponentialRolloutRate", "RateIncreaseCriteria"], null)
	is_object(ric)
	object.get(ric, "NumberOfNotifiedThings", "__pf_absent") != "__pf_absent"
	object.get(ric, "NumberOfSucceededThings", "__pf_absent") != "__pf_absent"
}
