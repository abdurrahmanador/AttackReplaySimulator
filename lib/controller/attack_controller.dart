import 'dart:async';
import 'dart:convert';

import 'package:get/get.dart';
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:latlong2/latlong.dart';
import '../models/attack_event.dart';

class AttackController extends GetxController {
  final wsUrl = 'ws://127.0.0.1:8000/ws/events';
  WebSocketChannel? _channel;
  StreamSubscription? _sub;

  // event list (newest first)
  RxList<AttackEvent> events = <AttackEvent>[].obs;

  // arcs: each arc is defined by src LatLng (attacker) and dst LatLng (target)
  RxList<Map<String, dynamic>> arcs = <Map<String, dynamic>>[].obs;

  // story queue (recent critical/high events)
  RxList<AttackEvent> storyQueue = <AttackEvent>[].obs;

  @override
  void onInit() {
    super.onInit();
    connect();
  }

  void connect() {
    disconnect();
    try {
      print("🔌 [WS] Connecting to $wsUrl ...");
      _channel = WebSocketChannel.connect(Uri.parse(wsUrl));

      // Send test message immediately after connecting
      Future.delayed(Duration(milliseconds: 100), () {
        try {
          _channel?.sink.add("test_connection");
          print("📤 [WS] Test message sent");
        } catch (e) {
          print("❌ [WS] Failed to send test: $e");
        }
      });

      _sub = _channel!.stream.listen(
        _onMessage,
        onDone: _onDone,
        onError: _onError,
      );
      print("✅ [WS] Connection attempt sent");
    } catch (e) {
      print('❌ [WS] Connect error: $e');
      _reconnectLater();
    }
  }

  void _onMessage(dynamic msg) {
    print("📩 [WS] Raw message received: $msg");
    try {
      final data = json.decode(msg as String) as Map<String, dynamic>;
      final type = data['type'] as String? ?? '';
      final payload = data['event'] ?? data;
      print("📦 [WS] Decoded type: $type");

      if (type == 'event:new') {
        final ev = AttackEvent.fromJson({'event': payload});
        events.insert(0, ev);
        print("🆕 [EVENT] New event added: ${ev.id}");
        _maybeAddStory(ev);
      } else if (type == 'event:update') {
        print("♻️ [EVENT] Update received");
        final updated = AttackEvent.fromJson({'event': payload});
        final idx = events.indexWhere((e) => e.id == updated.id);
        if (idx >= 0) {
          print("🔄 [EVENT] Updating existing event ${updated.id}");
          final merged = events[idx].copyWith(
            lat: updated.lat ?? events[idx].lat,
            lon: updated.lon ?? events[idx].lon,
            country: updated.country ?? events[idx].country,
            openPorts: updated.openPorts ?? events[idx].openPorts,
            providers: updated.providers ?? events[idx].providers,
          );
          events[idx] = merged;
          if (merged.lat != null && merged.lon != null) {
            print("🎯 [ARC] Creating arc for ${merged.id}");
            createArcForEvent(merged);
          }
        } else {
          print("➕ [EVENT] Adding new event from update: ${updated.id}");
          events.insert(0, updated);
          if (updated.lat != null && updated.lon != null) {
            createArcForEvent(updated);
          }
        }
      } else {
        print("⚠️ [WS] Unknown message type: $type");
      }
    } catch (e) {
      print('❌ [WS] Parse error: $e');
    }
  }

  void _onDone() {
    print('⚡ [WS] Connection closed by server, reconnecting...');
    _reconnectLater();
  }

  void _onError(e) {
    print('🔥 [WS] Error: $e');
    _reconnectLater();
  }

  void createArcForEvent(AttackEvent ev) {
    if (ev.lat == null || ev.lon == null) {
      print("🚫 [ARC] No coordinates for ${ev.id}");
      return;
    }

    final target = LatLng(ev.lat!, ev.lon!);
    final src = LatLng(20.0, 0.0);
    final arc = {
      'id': ev.id,
      'src': src,
      'dst': target,
      'color': colorForSeverityValue(ev.severity),
      'ts': ev.timestamp.millisecondsSinceEpoch,
    };
    arcs.insert(0, arc);
    print("✅ [ARC] Arc created for event ${ev.id}");

    Future.delayed(Duration(seconds: 12), () {
      arcs.removeWhere((a) => a['id'] == ev.id);
      print("🗑️ [ARC] Arc removed for event ${ev.id}");
    });
  }

  void _maybeAddStory(AttackEvent ev) {
    // Add critical/high events to story queue
    final sev = ev.severity.toLowerCase();
    if (sev == 'critical' || sev == 'high') {
      storyQueue.insert(0, ev);
      if (storyQueue.length > 10) storyQueue.removeLast(); // limit
    }
  }

  int colorForSeverityValue(String s) {
    switch (s.toLowerCase()) {
      case 'critical': return 0xFFFF3B30;
      case 'high': return 0xFFFF9500;
      case 'medium': return 0xFFFFD60A;
      default: return 0xFF34C759;
    }

  }


  void _reconnectLater() {
    Future.delayed(Duration(seconds: 5), () {
      connect();
    });
  }

  void disconnect() {
    try {
      _sub?.cancel();
    } catch (_) {}
    try {
      _channel?.sink.close();
    } catch (_) {}
    _sub = null;
    _channel = null;
  }

  @override
  void onClose() {
    disconnect();
    super.onClose();
  }
}