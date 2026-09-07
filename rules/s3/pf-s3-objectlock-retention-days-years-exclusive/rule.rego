package cdk_preflight

import rego.v1

_pf_s3oldy_fix := "Express the default retention period either in Days or in Years, not both"

_pf_s3oldy_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-objectlockconfiguration.html"

violation contains make_diag_full("pf-s3-objectlock-retention-days-years-exclusive", "ERROR", name,
	"Properties.ObjectLockConfiguration.Rule.DefaultRetention",
	sprintf("DefaultRetention sets %d of Days / Years; S3 requires exactly one", [n]),
	_pf_s3oldy_fix, _pf_s3oldy_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	dr := resolve(name, "Properties.ObjectLockConfiguration.Rule.DefaultRetention")
	is_object(dr)
	n := count([k | some k in ["Days", "Years"]; object.get(dr, k, "__pf_absent") != "__pf_absent"])
	n != 1
}
