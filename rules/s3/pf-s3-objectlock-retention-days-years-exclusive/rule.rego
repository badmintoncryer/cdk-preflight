package cdk_preflight

import rego.v1

_pf_s3oldy_fix := "Express the default retention period either in Days or in Years, not both"

_pf_s3oldy_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-objectlockconfiguration.html"

violation contains make_diag_full("pf-s3-objectlock-retention-days-years-exclusive", "ERROR", name,
	"Properties.ObjectLockConfiguration.Rule.DefaultRetention",
	sprintf("DefaultRetention sets %d of Days / Years; S3 requires exactly one (or neither when DefaultEventHold is set)", [n]),
	_pf_s3oldy_fix, _pf_s3oldy_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	dr := resolve(name, "Properties.ObjectLockConfiguration.Rule.DefaultRetention")
	is_object(dr)
	n := count([k | some k in ["Days", "Years"]; object.get(dr, k, "__pf_absent") != "__pf_absent"])
	n != 1
	not _pf_s3oldy_event_hold_only(dr, n)
}

# Variable retention: Mode plus DefaultEventHold with neither Days nor Years is
# accepted (bench 2026-11-16 us-east-1, CREATE_COMPLETE).
_pf_s3oldy_event_hold_only(dr, 0) if {
	object.get(dr, "DefaultEventHold", "__pf_absent") != "__pf_absent"
}
