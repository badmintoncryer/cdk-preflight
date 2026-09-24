package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-xray-group-notifications-require-insights", "ERROR", name,
	"Properties.InsightsConfiguration.NotificationsEnabled",
	"InsightsConfiguration enables notifications without enabling insights; CreateGroup fails with \"Notifications can be enabled for Insights enabled group only\"",
	"Set InsightsEnabled to true as well, or drop NotificationsEnabled",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-xray-group-insightsconfiguration.html") if {
	some name in resources_of_type("AWS::XRay::Group")
	ic := object.get(_pf_xraylib_props(name), "InsightsConfiguration", null)
	is_object(ic)
	_pf_xraylib_true(object.get(ic, "NotificationsEnabled", null))
	ie := object.get(ic, "InsightsEnabled", null)
	not _pf_xraylib_true(ie)
}
