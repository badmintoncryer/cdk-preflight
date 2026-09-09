package cdk_preflight

import rego.v1

_pf_cf_viewer_certificate_exactly_one_fix := "Keep only one of CloudFrontDefaultCertificate, AcmCertificateArn or IamCertificateId"

_pf_cf_viewer_certificate_exactly_one_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-viewercertificate.html"

violation contains make_diag_full("pf-cloudfront-viewer-certificate-exactly-one", "ERROR", name, "Properties.DistributionConfig.ViewerCertificate",
	sprintf("ViewerCertificate names %v certificate sources (%v); exactly one is allowed", [count(ks), ks]),
	_pf_cf_viewer_certificate_exactly_one_fix, _pf_cf_viewer_certificate_exactly_one_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	vc := object.get(_pf_cflib_config(name), "ViewerCertificate", null)
	is_object(vc)
	ks := {k | some k in ["CloudFrontDefaultCertificate", "AcmCertificateArn", "IamCertificateId"]; object.get(vc, k, "__pf_absent") != "__pf_absent"}
	count(ks) > 1
}
