package cdk_preflight

import rego.v1

_pf_cf_continuous_deployment_policy_excludes_staging_fix := "Attach the continuous deployment policy to the primary distribution only"

_pf_cf_continuous_deployment_policy_excludes_staging_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-continuous-deployment-policy-excludes-staging", "ERROR", name, "Properties.DistributionConfig",
	"ContinuousDeploymentPolicyId belongs on the primary distribution, not the staging one",
	_pf_cf_continuous_deployment_policy_excludes_staging_fix, _pf_cf_continuous_deployment_policy_excludes_staging_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	cfg := _pf_cflib_config(name)
	object.get(cfg, "Staging", false) == true
	object.get(cfg, "ContinuousDeploymentPolicyId", "__pf_absent") != "__pf_absent"
}
