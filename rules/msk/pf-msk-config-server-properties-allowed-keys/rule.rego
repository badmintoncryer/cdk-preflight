package cdk_preflight

import rego.v1

# Amazon MSK does not accept arbitrary Apache Kafka broker properties. CreateConfiguration checks
# every key in ServerProperties against a fixed allow-list (the "Custom Amazon MSK configurations"
# table) and rejects anything else -- a read-only broker property (advertised.listeners), a
# per-broker property (broker.id), or a line that is not key=value at all -- with
# "Key '<k>' is not supported by at least one Apache Kafka version".
# The list is static: passing KafkaVersionsList does not widen it.
_pf_mskspk_allowed := {
	"allow.everyone.if.no.acl.found",
	"auto.create.topics.enable",
	"compression.type",
	"connections.max.idle.ms",
	"custom.advertised.listeners",
	"default.replication.factor",
	"delete.topic.enable",
	"group.initial.rebalance.delay.ms",
	"group.max.session.timeout.ms",
	"group.min.session.timeout.ms",
	"leader.imbalance.per.broker.percentage",
	"log.cleaner.delete.retention.ms",
	"log.cleaner.min.cleanable.ratio",
	"log.cleanup.policy",
	"log.flush.interval.messages",
	"log.flush.interval.ms",
	"log.message.timestamp.difference.max.ms",
	"log.message.timestamp.type",
	"log.retention.bytes",
	"log.retention.hours",
	"log.retention.minutes",
	"log.retention.ms",
	"log.roll.ms",
	"log.segment.bytes",
	"max.incremental.fetch.session.cache.slots",
	"message.max.bytes",
	"min.insync.replicas",
	"num.io.threads",
	"num.network.threads",
	"num.partitions",
	"num.recovery.threads.per.data.dir",
	"num.replica.fetchers",
	"offsets.retention.minutes",
	"offsets.topic.replication.factor",
	"replica.fetch.max.bytes",
	"replica.fetch.response.max.bytes",
	"replica.lag.time.max.ms",
	"replica.selector.class",
	"replica.socket.receive.buffer.bytes",
	"socket.receive.buffer.bytes",
	"socket.request.max.bytes",
	"socket.send.buffer.bytes",
	"transaction.max.timeout.ms",
	"transaction.state.log.min.isr",
	"transaction.state.log.replication.factor",
	"transactional.id.expiration.ms",
	"unclean.leader.election.enable",
	"zookeeper.connection.timeout.ms",
	"zookeeper.session.timeout.ms",
}

# A properties line is "key=value"; a line with no '=' is a key with an empty value, which is how a
# JSON blob or stray prose lands here. ponytail: no support for backslash line continuations --
# a continued line is skipped, so the rule misses rather than false-fires.
_pf_mskspk_key(line) := k if {
	i := indexof(line, "=")
	i > 0
	k := trim_space(substring(line, 0, i))
}

_pf_mskspk_key(line) := line if {
	indexof(line, "=") <= 0
}

_pf_mskspk_bad(name) := ks if {
	s := resolve(name, "Properties.ServerProperties")
	is_string(s)
	ks := [k |
		some ln in split(s, "\n")
		t := trim_space(ln)
		t != ""
		not startswith(t, "#")
		not startswith(t, "!")
		k := _pf_mskspk_key(t)
		not k in _pf_mskspk_allowed
	]
}

violation contains make_diag_full("pf-msk-config-server-properties-allowed-keys", "ERROR", name,
	"Properties.ServerProperties",
	sprintf("ServerProperties sets %s, which Amazon MSK does not allow in a custom configuration; the create fails with \"Key '%s' is not supported by at least one Apache Kafka version\"", [concat(", ", bad), bad[0]]),
	"Keep ServerProperties to the properties listed under \"Custom Amazon MSK configurations\" (read-only and per-broker Kafka properties cannot be set)",
	"https://docs.aws.amazon.com/msk/latest/developerguide/msk-configuration-properties.html") if {
	some name in resources_of_type("AWS::MSK::Configuration")
	bad := _pf_mskspk_bad(name)
	count(bad) > 0
}
