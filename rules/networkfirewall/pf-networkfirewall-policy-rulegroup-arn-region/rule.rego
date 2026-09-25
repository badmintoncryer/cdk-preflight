package cdk_preflight

import rego.v1

# Rule groups are regional: RAM shares them across accounts but never across
# regions. An imported ARN carries its region and nothing below the service
# compares it with the stack's. Measured 2026-09-25: a rule group ARN from
# another region answers "rule group ARN is invalid", which is a different
# message from the "rule group ARN does not exist" a same-region ARN that is
# missing gets - so the region is what the service is objecting to.
_pf_nfwparg contains [name, kind, i, r] if {
	some [name, kind, i, _] in _pf_nfwlib_policy_ref
	r := _pf_nfwlib_arn_region(_pf_nfwlib_ref_arn(name, kind, i), "network-firewall")
}

violation contains make_diag_full("pf-networkfirewall-policy-rulegroup-arn-region", "ERROR", name,
	sprintf("Properties.FirewallPolicy.%sRuleGroupReferences.%d.ResourceArn", [kind, i]),
	sprintf("the rule group is in '%v' but the policy deploys to '%v'; CreateFirewallPolicy answers \"rule group ARN is invalid\"", [r, region]),
	"Reference a rule group in the policy's own region",
	"https://docs.aws.amazon.com/network-firewall/latest/developerguide/quotas.html") if {
	some [name, kind, i, r] in _pf_nfwparg
	region := data.cdk_preflight.deploy_region
	is_string(region)
	r != region
}
