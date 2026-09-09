package cdk_preflight

import rego.v1

_pf_cf_continuous_deployment_staging_dns_count_fix := "List a single staging distribution domain name"

_pf_cf_continuous_deployment_staging_dns_count_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-continuousdeploymentpolicy.html"

violation contains make_diag_full("pf-cloudfront-continuous-deployment-staging-dns-count", "ERROR", name, "Properties.ContinuousDeploymentPolicyConfig.StagingDistributionDnsNames",
	sprintf("%v staging DNS names are declared; CloudFront accepts exactly one", [count(ns)]),
	_pf_cf_continuous_deployment_staging_dns_count_fix, _pf_cf_continuous_deployment_staging_dns_count_url) if {
	some name in resources_of_type("AWS::CloudFront::ContinuousDeploymentPolicy")
	cfgv := _pf_cflib_props(name, "ContinuousDeploymentPolicyConfig")
	ns := object.get(cfgv, "StagingDistributionDnsNames", [])
	count(ns) > 1
}
