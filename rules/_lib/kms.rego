package cdk_preflight

import rego.v1

# An AWS managed key named by alias: "alias/aws/<svc>" or its alias ARN. Key IDs
# and key ARNs of the same key are not recognizable from the template.
_pf_amk_alias(k, svc) if k == sprintf("alias/aws/%s", [svc])

_pf_amk_alias(k, svc) if {
	startswith(k, "arn:")
	endswith(k, sprintf(":alias/aws/%s", [svc]))
}
