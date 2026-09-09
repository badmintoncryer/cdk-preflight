package cdk_preflight

import rego.v1

_pf_cf_viewer_certificate_sni_min_protocol_fix := "Use TLSv1.2_2021 (or another TLS version) instead of SSLv3"

_pf_cf_viewer_certificate_sni_min_protocol_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-viewercertificate.html"

violation contains make_diag_full("pf-cloudfront-viewer-certificate-sni-min-protocol", "ERROR", name, "Properties.DistributionConfig.ViewerCertificate",
	"SslSupportMethod sni-only cannot be combined with MinimumProtocolVersion SSLv3",
	_pf_cf_viewer_certificate_sni_min_protocol_fix, _pf_cf_viewer_certificate_sni_min_protocol_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	vc := object.get(_pf_cflib_config(name), "ViewerCertificate", null)
	is_object(vc)
	object.get(vc, "SslSupportMethod", null) == "sni-only"
	object.get(vc, "MinimumProtocolVersion", null) == "SSLv3"
}
