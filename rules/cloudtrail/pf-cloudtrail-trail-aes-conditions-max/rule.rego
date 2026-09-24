package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cloudtrail-trail-aes-conditions-max", "ERROR", name,
	"Properties.AdvancedEventSelectors",
	sprintf("the trail's advanced event selectors hold %v condition values in total; CloudTrail allows 500 per trail", [n]),
	"Keep the total number of condition values across every advanced event selector at 500 or fewer",
	"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/WhatIsCloudTrail-Limits.html") if {
	some name in resources_of_type("AWS::CloudTrail::Trail")
	n := _pf_ctlib_aes_condition_total(name)
	n > 500
}
