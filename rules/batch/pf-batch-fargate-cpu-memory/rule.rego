package cdk_preflight

import rego.v1

_pf_batchfcm_url := "https://docs.aws.amazon.com/batch/latest/userguide/fargate.html"

# Memory spec per vCPU tier: 0.25 is an explicit set; the rest are
# [min, max, step] arithmetic ranges. Keys are numbers so "1.0" and
# "1" both land on the same tier after to_number.
_pf_batchfcm_set := {512, 1024, 2048}

_pf_batchfcm_range := {0.5: [1024, 4096, 1024], 1: [2048, 8192, 1024], 2: [4096, 16384, 1024], 4: [8192, 30720, 1024], 8: [16384, 61440, 4096], 16: [32768, 122880, 8192]}

_pf_batchfcm_fargate(name) if {
	some pc in flatten_list(name, "Properties.PlatformCapabilities")
	pc.value == "FARGATE"
}

_pf_batchfcm_req(name, rtype) := v if {
	some item in flatten_list(name, "Properties.ContainerProperties.ResourceRequirements")
	entry := item.value
	is_object(entry)
	object.get(entry, "Type", "") == rtype
	raw := object.get(entry, "Value", null)
	is_string(raw)
	v := to_number(raw)
}

_pf_batchfcm_bad(v, m) if {
	v == 0.25
	not m in _pf_batchfcm_set
}

_pf_batchfcm_bad(v, m) if {
	spec := _pf_batchfcm_range[v]
	m < spec[0]
}

_pf_batchfcm_bad(v, m) if {
	spec := _pf_batchfcm_range[v]
	m > spec[1]
}

_pf_batchfcm_bad(v, m) if {
	spec := _pf_batchfcm_range[v]
	(m - spec[0]) % spec[2] != 0
}

_pf_batchfcm_tier(v) if v == 0.25

_pf_batchfcm_tier(v) if _pf_batchfcm_range[v]

violation contains make_diag_full("pf-batch-fargate-cpu-memory", "ERROR", name,
	"Properties.ContainerProperties.ResourceRequirements",
	sprintf("VCPU %v is not a Fargate tier (0.25, 0.5, 1, 2, 4, 8, 16); Batch rejects it with \"Fargate resource requirements ... not valid.\"", [v]),
	"Use one of the Fargate vCPU tiers",
	_pf_batchfcm_url) if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batchfcm_fargate(name)
	v := _pf_batchfcm_req(name, "VCPU")
	not _pf_batchfcm_tier(v)
}

violation contains make_diag_full("pf-batch-fargate-cpu-memory", "ERROR", name,
	"Properties.ContainerProperties.ResourceRequirements",
	sprintf("MEMORY %v MiB is not valid for VCPU %v; Batch rejects it with \"Fargate resource requirements (%v vCPU, %v MiB) not valid.\"", [m, v, v, m]),
	"Pick a memory value from the tier's supported list",
	_pf_batchfcm_url) if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batchfcm_fargate(name)
	v := _pf_batchfcm_req(name, "VCPU")
	m := _pf_batchfcm_req(name, "MEMORY")
	_pf_batchfcm_bad(v, m)
}
