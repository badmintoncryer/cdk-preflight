package cdk_preflight

import rego.v1

_pf_wafbm_url := "https://docs.aws.amazon.com/waf/latest/APIReference/API_ByteMatchStatement.html"

_pf_wafbm_fix := "Provide either SearchString or SearchStringBase64 (not both), keep it under 200 bytes and non-blank, and restrict CONTAINS_WORD search strings to letters, digits and underscore"

_pf_wafbm contains [name, pp, b] if {
	some [name, i, p, kind, b] in _pf_waflib_leaves
	kind == "ByteMatchStatement"
	pp := _pf_waflib_path(i, array.concat(p, ["ByteMatchStatement"]))
}

_pf_wafbm_has(b, k) if object.get(b, k, "__pf_absent") != "__pf_absent"

violation contains make_diag_full("pf-wafv2-byte-match", "ERROR", name, pp,
	"both SearchString and SearchStringBase64 are set; the CloudFormation handler fails with \"You must only specify exactly one of SearchString and SearchStringBase64\"",
	_pf_wafbm_fix, _pf_wafbm_url) if {
	some [name, pp, b] in _pf_wafbm
	_pf_wafbm_has(b, "SearchString")
	_pf_wafbm_has(b, "SearchStringBase64")
}

violation contains make_diag_full("pf-wafv2-byte-match", "ERROR", name, pp,
	"neither SearchString nor SearchStringBase64 is set; the CloudFormation handler fails with \"You must only specify exactly one of SearchString and SearchStringBase64\"",
	_pf_wafbm_fix, _pf_wafbm_url) if {
	some [name, pp, b] in _pf_wafbm
	not _pf_wafbm_has(b, "SearchString")
	not _pf_wafbm_has(b, "SearchStringBase64")
}

violation contains make_diag_full("pf-wafv2-byte-match", "ERROR", name, sprintf("%s.SearchString", [pp]),
	sprintf("search string is %d characters; at most 200 bytes are allowed (the create call fails with WAFLimitsExceededException NUM_BYTES_IN_BYTEMATCH_SEARCHSTRING)", [count(s)]),
	_pf_wafbm_fix, _pf_wafbm_url) if {
	some [name, pp, b] in _pf_wafbm
	s := b.SearchString
	is_string(s)
	count(s) > 200
}

violation contains make_diag_full("pf-wafv2-byte-match", "ERROR", name, sprintf("%s.SearchString", [pp]),
	"search string is empty or whitespace only; the create call fails with \"Member must satisfy regular expression pattern: .*\\S.*\"",
	_pf_wafbm_fix, _pf_wafbm_url) if {
	some [name, pp, b] in _pf_wafbm
	s := b.SearchString
	is_string(s)
	not regex.match("\\S", s)
}

violation contains make_diag_full("pf-wafv2-byte-match", "ERROR", name, sprintf("%s.SearchString", [pp]),
	sprintf("CONTAINS_WORD search string '%s' must contain only letters, digits and underscore; the create call fails with \"Invalid search string ... for CONTAINS_WORD constraint ... Only alphanumeric characters and underscores are allowed.\"", [s]),
	_pf_wafbm_fix, _pf_wafbm_url) if {
	some [name, pp, b] in _pf_wafbm
	b.PositionalConstraint == "CONTAINS_WORD"
	s := b.SearchString
	is_string(s)
	not regex.match("^[A-Za-z0-9_]+$", s)
}
