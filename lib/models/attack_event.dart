class AttackEvent {
  final String id;
  final DateTime timestamp;
  final String srcIp;
  final String attackType;
  final String severity;
  final String raw;

  // enrichment
  final double? lat;
  final double? lon;
  final String? country;
  final List<int>? openPorts;
  final Map<String, dynamic>? providers;

  AttackEvent({
    required this.id,
    required this.timestamp,
    required this.srcIp,
    required this.attackType,
    required this.severity,
    required this.raw,
    this.lat,
    this.lon,
    this.country,
    this.openPorts,
    this.providers,
  });

  factory AttackEvent.fromJson(Map<String, dynamic> json) {
    final e = json['event'] ?? json;
    final enriched = e['enriched'] ?? {};
    final geo = enriched != null ? enriched['geo'] ?? {} : {};
    final openPortsRaw = enriched != null ? enriched['open_ports'] : null;

    return AttackEvent(
      id: e['event_id'] ?? '',
      timestamp: DateTime.tryParse(e['timestamp'] ?? '') ?? DateTime.now(),
      srcIp: e['src_ip'] ?? '',
      attackType: e['attack_type'] ?? '',
      severity: e['severity'] ?? 'medium',
      raw: e['raw'] ?? '',
      lat: (geo != null && geo['lat'] != null) ? (geo['lat'] as num).toDouble() : null,
      lon: (geo != null && geo['lon'] != null) ? (geo['lon'] as num).toDouble() : null,
      country: geo != null ? (geo['country'] as String?) : null,
      openPorts: openPortsRaw != null
          ? List<int>.from(openPortsRaw.map<int>((p) => (p as num).toInt()))
          : null,
      providers: enriched != null ? (enriched['providers'] as Map<String, dynamic>?) : null,
    );
  }

  AttackEvent copyWith({
    double? lat,
    double? lon,
    String? country,
    List<int>? openPorts,
    Map<String, dynamic>? providers,
  }) {
    return AttackEvent(
      id: id,
      timestamp: timestamp,
      srcIp: srcIp,
      attackType: attackType,
      severity: severity,
      raw: raw,
      lat: lat ?? this.lat,
      lon: lon ?? this.lon,
      country: country ?? this.country,
      openPorts: openPorts ?? this.openPorts,
      providers: providers ?? this.providers,
    );
  }
}