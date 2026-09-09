package cdk_preflight

import rego.v1

_pf_cf_viewer_certificate_vip_deprecated_fix := "Use sni-only"

_pf_cf_viewer_certificate_vip_deprecated_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-viewercertificate.html"

violation contains make_diag_full("pf-cloudfront-viewer-certificate-vip-deprecated", "ERROR", name, "Properties.DistributionConfig.ViewerCertificate",
	"SslSupportMethod vip (dedicated IP) is no longer available for new distributions",
	_pf_cf_viewer_certificate_vip_deprecated_fix, _pf_cf_viewer_certificate_vip_deprecated_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	vc := object.get(_pf_cflib_config(name), "ViewerCertificate", null)
	is_object(vc)
	object.get(vc, "SslSupportMethod", null) == "vip"
}
