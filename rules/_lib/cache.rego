package cdk_preflight

import rego.v1

# Shared helpers for the ElastiCache and MemoryDB rules. Both services use the
# same maintenance / snapshot window grammar, the same endpoint port range and
# the same identifier rules, so the parsing lives here once.
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

# to_number("03") is undefined in the engine's Rego build, so digits go
# through a lookup table (same trick as pf-rds-window-overlap).
_pf_cachelib_digit := {"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9}

_pf_cachelib_days := {"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}

# "HH:MM" -> minutes of day; undefined for anything else.
_pf_cachelib_min(t) := m if {
	is_string(t)
	regex.match(`^([01][0-9]|2[0-3]):[0-5][0-9]$`, t)
	h := (_pf_cachelib_digit[substring(t, 0, 1)] * 10) + _pf_cachelib_digit[substring(t, 1, 1)]
	mi := (_pf_cachelib_digit[substring(t, 3, 1)] * 10) + _pf_cachelib_digit[substring(t, 4, 1)]
	m := (h * 60) + mi
}

# "ddd:hh24:mi-ddd:hh24:mi" -> [start day, start minutes, end day, end minutes].
_pf_cachelib_window(w) := [d1, m1, d2, m2] if {
	is_string(w)
	parts := split(lower(w), "-")
	count(parts) == 2
	p1 := split(parts[0], ":")
	p2 := split(parts[1], ":")
	count(p1) == 3
	count(p2) == 3
	d1 := _pf_cachelib_days[p1[0]]
	d2 := _pf_cachelib_days[p2[0]]
	m1 := _pf_cachelib_min(sprintf("%s:%s", [p1[1], p1[2]]))
	m2 := _pf_cachelib_min(sprintf("%s:%s", [p2[1], p2[2]]))
}

# Length of a maintenance window in minutes (wrapping around the week).
_pf_cachelib_window_minutes(w) := n if {
	[d1, m1, d2, m2] := _pf_cachelib_window(w)
	start := (d1 * 1440) + m1
	end := (d2 * 1440) + m2
	n := ((end - start) + 10080) % 10080
}

# "hh24:mi-hh24:mi" -> [start minutes, end minutes] of a daily window.
_pf_cachelib_daily(w) := [s, e] if {
	is_string(w)
	parts := split(w, "-")
	count(parts) == 2
	s := _pf_cachelib_min(parts[0])
	e := _pf_cachelib_min(parts[1])
}

# The snapshot window recurs daily, so a same-day maintenance window overlaps
# whenever the two time-of-day intervals intersect (mirrors pf-rds-window-overlap;
# a window that spans two days is left alone).
_pf_cachelib_overlap(mw, sw) if {
	[d1, m1, d2, m2] := _pf_cachelib_window(mw)
	d1 == d2
	m1 < m2
	[s, e] := _pf_cachelib_daily(sw)
	s < e
	s < m2
	m1 < e
}

# ElastiCache and MemoryDB both accept 1150-8004 and 8006-65535.
_pf_cachelib_port_ok(p) if {
	p >= 1150
	p <= 8004
}

_pf_cachelib_port_ok(p) if {
	p >= 8006
	p <= 65535
}

# Identifiers: begin with a letter, letters/digits/hyphens only, no two
# consecutive hyphens and no trailing hyphen.
_pf_cachelib_identifier_ok(s) if regex.match(`^[A-Za-z][A-Za-z0-9]*(-[A-Za-z0-9]+)*$`, s)

# Data tiering is only supported on the r6gd families (cache.r6gd.* / db.r6gd.*).
_pf_cachelib_r6gd(t) if {
	is_string(t)
	parts := split(t, ".")
	count(parts) >= 2
	parts[1] == "r6gd"
}

# [partition, service, region, account, resource...] of a literal ARN.
_pf_cachelib_arn(s) := parts if {
	is_string(s)
	startswith(s, "arn:")
	parts := split(s, ":")
	count(parts) >= 6
}

# A literal string a user wrote, not a resolved Ref / GetAtt logical id.
_pf_cachelib_lit(v) if {
	is_string(v)
	not input.resources[v]
}

_pf_cachelib_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}
