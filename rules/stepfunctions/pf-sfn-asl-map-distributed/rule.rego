package cdk_preflight

import rego.v1

_pf_sfnmd_url := "https://docs.aws.amazon.com/step-functions/latest/dg/state-map-distributed.html"

_pf_sfnmd_fix := "Set ProcessorConfig.ExecutionType for DISTRIBUTED mode only, and shape ItemReader per the Distributed Map documentation"

_pf_sfnmd_cfg contains [name, p, sname, key, cfg] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	some key in ["ItemProcessor", "Iterator"]
	proc := object.get(st, key, null)
	is_object(proc)
	cfg := object.get(proc, "ProcessorConfig", null)
	is_object(cfg)
}

violation contains make_diag_full("pf-sfn-asl-map-distributed", "ERROR", name,
	sprintf("%s.%s.ProcessorConfig", [_pf_sfnlib_path(name, p, sname), key]),
	sprintf("Map state '%s' runs in DISTRIBUTED mode without ExecutionType; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: These fields are required: [ExecutionType]\"", [sname]),
	_pf_sfnmd_fix, _pf_sfnmd_url) if {
	some [name, p, sname, key, cfg] in _pf_sfnmd_cfg
	object.get(cfg, "Mode", null) == "DISTRIBUTED"
	not _pf_sfnlib_has(cfg, "ExecutionType")
}

violation contains make_diag_full("pf-sfn-asl-map-distributed", "ERROR", name,
	sprintf("%s.%s.ProcessorConfig.ExecutionType", [_pf_sfnlib_path(name, p, sname), key]),
	sprintf("Map state '%s' ExecutionType '%s' is not STANDARD or EXPRESS; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Value should be one of the following: [STANDARD, EXPRESS]\"", [sname, et]),
	_pf_sfnmd_fix, _pf_sfnmd_url) if {
	some [name, p, sname, key, cfg] in _pf_sfnmd_cfg
	et := object.get(cfg, "ExecutionType", null)
	is_string(et)
	not et in {"STANDARD", "EXPRESS"}
}

violation contains make_diag_full("pf-sfn-asl-map-distributed", "ERROR", name,
	sprintf("%s.%s.ProcessorConfig.ExecutionType", [_pf_sfnlib_path(name, p, sname), key]),
	sprintf("Map state '%s' sets ExecutionType in INLINE mode; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Field 'ExecutionType' is not supported\"", [sname]),
	_pf_sfnmd_fix, _pf_sfnmd_url) if {
	some [name, p, sname, key, cfg] in _pf_sfnmd_cfg
	object.get(cfg, "Mode", null) == "INLINE"
	_pf_sfnlib_has(cfg, "ExecutionType")
}

_pf_sfnmd_reader contains [name, p, sname, ir] if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	object.get(st, "Type", null) == "Map"
	ir := object.get(st, "ItemReader", null)
	is_object(ir)
}

violation contains make_diag_full("pf-sfn-asl-map-distributed", "ERROR", name,
	sprintf("%s.ItemReader.Resource", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("Map state '%s' ItemReader.Resource '%s' is not s3:getObject or s3:listObjectsV2; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: The field 'Resource' does not match any of the allowed values\"", [sname, res]),
	_pf_sfnmd_fix, _pf_sfnmd_url) if {
	some [name, p, sname, ir] in _pf_sfnmd_reader
	res := object.get(ir, "Resource", null)
	is_string(res)
	not contains(res, "${")
	not regex.match("^arn:[^:]+:states:::s3:(getObject|listObjectsV2)$", res)
}

violation contains make_diag_full("pf-sfn-asl-map-distributed", "ERROR", name,
	sprintf("%s.ItemReader.ReaderConfig", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("Map state '%s' reads CSV without CSVHeaderLocation; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: The field 'CSVHeaderLocation' is required\"", [sname]),
	_pf_sfnmd_fix, _pf_sfnmd_url) if {
	some [name, p, sname, ir] in _pf_sfnmd_reader
	rc := object.get(ir, "ReaderConfig", null)
	is_object(rc)
	object.get(rc, "InputType", null) == "CSV"
	not _pf_sfnlib_has(rc, "CSVHeaderLocation")
}

violation contains make_diag_full("pf-sfn-asl-map-distributed", "ERROR", name,
	sprintf("%s.ItemReader.ReaderConfig.CSVHeaderLocation", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("Map state '%s' reads JSON but sets CSVHeaderLocation; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Field 'CSVHeaderLocation' is not supported\"", [sname]),
	_pf_sfnmd_fix, _pf_sfnmd_url) if {
	some [name, p, sname, ir] in _pf_sfnmd_reader
	rc := object.get(ir, "ReaderConfig", null)
	is_object(rc)
	object.get(rc, "InputType", null) == "JSON"
	_pf_sfnlib_has(rc, "CSVHeaderLocation")
}

violation contains make_diag_full("pf-sfn-asl-map-distributed", "ERROR", name,
	sprintf("%s.ItemReader.ReaderConfig", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("Map state '%s' sets CSVHeaderLocation GIVEN without CSVHeaders; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: These fields are required: [CSVHeaders]\"", [sname]),
	_pf_sfnmd_fix, _pf_sfnmd_url) if {
	some [name, p, sname, ir] in _pf_sfnmd_reader
	rc := object.get(ir, "ReaderConfig", null)
	is_object(rc)
	object.get(rc, "CSVHeaderLocation", null) == "GIVEN"
	not _pf_sfnlib_has(rc, "CSVHeaders")
}
