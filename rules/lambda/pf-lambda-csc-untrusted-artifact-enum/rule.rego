package cdk_preflight

import rego.v1

_pf_lcsue_fix := "Set UntrustedArtifactOnDeployment to Warn or Enforce"

_pf_lcsue_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-codesigningconfig-codesigningpolicies.html"

violation contains make_diag_full("pf-lambda-csc-untrusted-artifact-enum", "ERROR", name,
	"Properties.CodeSigningPolicies.UntrustedArtifactOnDeployment",
	sprintf("UntrustedArtifactOnDeployment '%v'; the policy is either Warn or Enforce", [v]),
	_pf_lcsue_fix, _pf_lcsue_url) if {
	some name in _pf_lam_csc
	pol := _pf_lam_obj(_pf_lam_props(name), "CodeSigningPolicies")
	v := object.get(pol, "UntrustedArtifactOnDeployment", "Warn")
	is_string(v)
	not v in {"Warn", "Enforce"}
}
