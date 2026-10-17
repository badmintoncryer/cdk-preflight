package cdk_preflight

import rego.v1

# LlmExtractionConfig.Validation takes one of StringValidation /
# StringListValidation / NumberValidation regardless of the entry's Type.
# CreateMemory accepts only the one that matches Type (STRING / STRINGLIST /
# NUMBER), and rejects a NumberValidation whose MinValue exceeds MaxValue.
_pf_acmvt_want := {"StringValidation": "STRING", "StringListValidation": "STRINGLIST", "NumberValidation": "NUMBER"}

_pf_acmvt_validation(e) := v if {
	v := e.ExtractionConfig.LlmExtractionConfig.Validation
	is_object(v)
}

violation contains make_diag_full("pf-agentcore-memory-metadata-validation-type", "ERROR", name,
	sprintf("Properties.MemoryStrategies.%d.%s.MemoryRecordSchema.MetadataSchema.%d.ExtractionConfig.LlmExtractionConfig.Validation.%s", [sc.index, sc.kind, i, vk]),
	sprintf("Metadata key '%s' has Type %s but uses %s; CreateMemory accepts %s only on %s keys", [object.get(e, "Key", "<unnamed>"), e.Type, vk, vk, want]),
	"Use the Validation that matches Type (STRING: StringValidation, STRINGLIST: StringListValidation, NUMBER: NumberValidation)",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/long-term-memory-metadata.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Memory")
	some sc in _pf_acmem_schemas(name)
	some i, e in sc.entries
	is_object(e)
	is_string(object.get(e, "Type", null))
	some vk, _ in _pf_acmvt_validation(e)
	want := _pf_acmvt_want[vk]
	e.Type != want
}

violation contains make_diag_full("pf-agentcore-memory-metadata-validation-type", "ERROR", name,
	sprintf("Properties.MemoryStrategies.%d.%s.MemoryRecordSchema.MetadataSchema.%d.ExtractionConfig.LlmExtractionConfig.Validation.NumberValidation", [sc.index, sc.kind, i]),
	sprintf("Metadata key '%s' has NumberValidation MinValue %v greater than MaxValue %v; CreateMemory rejects it", [object.get(e, "Key", "<unnamed>"), nv.MinValue, nv.MaxValue]),
	"Set MinValue to at most MaxValue",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/long-term-memory-metadata.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Memory")
	some sc in _pf_acmem_schemas(name)
	some i, e in sc.entries
	is_object(e)
	nv := _pf_acmvt_validation(e).NumberValidation
	is_number(nv.MinValue)
	is_number(nv.MaxValue)
	nv.MinValue > nv.MaxValue
}
