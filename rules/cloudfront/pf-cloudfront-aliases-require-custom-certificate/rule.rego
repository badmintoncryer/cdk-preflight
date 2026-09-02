package cdk_preflight

import rego.v1

_pf_cf_aliascert_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudfront-distribution-viewercertificate.html"

_pf_cf_aliascert_fix := "Attach an ACM certificate (AcmCertificateArn, us-east-1) or an IAM certificate, together with SslSupportMethod and MinimumProtocolVersion"

_pf_cf_aliascert_count(name) := count([1 |
	some _ in flatten_list(name, "Properties.DistributionConfig.Aliases")
])

violation contains make_diag_full("pf-cloudfront-aliases-require-custom-certificate", "ERROR", name,
	"Properties.DistributionConfig.ViewerCertificate",
	"A distribution with Aliases cannot use the CloudFront default certificate",
	_pf_cf_aliascert_fix, _pf_cf_aliascert_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	_pf_cf_aliascert_count(name) > 0
	resolve(name, "Properties.DistributionConfig.ViewerCertificate.CloudFrontDefaultCertificate") == true
}
