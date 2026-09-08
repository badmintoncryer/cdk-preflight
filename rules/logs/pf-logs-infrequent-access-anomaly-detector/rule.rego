package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-infrequent-access-anomaly-detector", "ERROR", name,
	"Properties.LogGroupArnList",
	"One of the detector's log groups uses the Infrequent Access log class; CreateLogAnomalyDetector fails with \"This operation is only supported on the Standard log class.\"",
	"Point the detector at Standard-class log groups (LogGroupClass: STANDARD, the default)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-logs-loggroup.html") if {
	some name in resources_of_type("AWS::Logs::LogAnomalyDetector")
	some item in flatten_list(name, "Properties.LogGroupArnList")
	some g in _pf_lglib_groups(_pf_lglib_ref(item.value))
	_pf_lglib_ia(g)
}
