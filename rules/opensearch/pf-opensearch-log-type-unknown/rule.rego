package cdk_preflight

import rego.v1

# Allowlist, hence WARN: the set is the enum CreateDomain printed on
# 2026-09-25. The documentation still lists four - TASK_DETAILS_LOGS is the
# one AWS added without updating it - so treating a sixth as an error would
# be betting the same way twice.
_pf_oslt_known := {"INDEX_SLOW_LOGS", "SEARCH_SLOW_LOGS", "ES_APPLICATION_LOGS", "AUDIT_LOGS", "TASK_DETAILS_LOGS"}

violation contains make_diag_full("pf-opensearch-log-type-unknown", "WARN", name,
	"Properties.LogPublishingOptions",
	sprintf("\"%v\" is not a log type the service knows; CreateDomain answers \"Map keys must satisfy constraint: [Member must satisfy enum value set: [INDEX_SLOW_LOGS, TASK_DETAILS_LOGS, ES_APPLICATION_LOGS, AUDIT_LOGS, SEARCH_SLOW_LOGS]]\"", [k]),
	"Use one of INDEX_SLOW_LOGS, SEARCH_SLOW_LOGS, ES_APPLICATION_LOGS, AUDIT_LOGS, TASK_DETAILS_LOGS",
	"https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_CreateDomain.html") if {
	some name in _pf_os_domains
	opts := _pf_os_at(name, "LogPublishingOptions")
	is_object(opts)
	some k, _v in opts
	not k in _pf_oslt_known
}
