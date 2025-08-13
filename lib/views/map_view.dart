import 'dart:math';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter_map/flutter_map.dart';
import 'package:get/get.dart';
import 'package:latlong2/latlong.dart';
import '../controller/attack_controller.dart';

class MapView extends StatefulWidget {
  const MapView({Key? key}) : super(key: key);

  @override
  State<MapView> createState() => _MapViewState();
}

class _MapViewState extends State<MapView> with SingleTickerProviderStateMixin {
  final AttackController ctrl = Get.find();
  late final AnimationController _anim;
  final MapController mapController = MapController();

  @override
  void initState() {
    super.initState();
    _anim = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 2000),
    )..repeat();
  }

  @override
  void dispose() {
    _anim.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Obx(() {
      final arcs = ctrl.arcs.toList();
      final markers = ctrl.events
          .where((e) => e.lat != null && e.lon != null)
          .map((e) => Marker(
        point: LatLng(e.lat!, e.lon!),
        width: 36,
        height: 36,
        child: Icon(
          Icons.security,
          color: Color(ctrl.colorForSeverityValue(e.severity)),
          size: 24,
        ),
      ))
          .toList();

      return Stack(
        children: [
          FlutterMap(
            mapController: mapController,
            options: MapOptions(
              initialCenter: LatLng(20, 0),
              initialZoom: 2.2,
            ),
            children: [
              TileLayer(
                urlTemplate: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
                userAgentPackageName: 'com.abdurrahman.attackreplay',
              ),
              MarkerLayer(markers: markers),
            ],
          ),
          Positioned.fill(
            child: IgnorePointer(
              child: AnimatedBuilder(
                animation: _anim,
                builder: (context, child) {
                  // Only draw arcs when the map has a camera
                  if (mapController.camera == null) {
                    return const SizedBox.shrink();
                  }
                  return CustomPaint(
                    painter: ArcPainter(
                      arcs,
                      mapController.camera!,
                      progress: _anim.value,
                    ),
                  );
                },
              ),
            ),
          ),
        ],
      );
    });
  }
}

class ArcPainter extends CustomPainter {
  final List<Map<String, dynamic>> arcs;
  final MapCamera camera;
  final double progress;

  ArcPainter(this.arcs, this.camera, {this.progress = 0.0});

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round;

    for (final arc in arcs) {
      try {
        final LatLng srcLatLng = arc['src'] as LatLng;
        final LatLng dstLatLng = arc['dst'] as LatLng;

        final src = _latLngToOffset(srcLatLng);
        final dst = _latLngToOffset(dstLatLng);

        if (_isOffScreen(src, dst, size)) continue;

        final mid = (src + dst) / 2;
        final dx = dst.dx - src.dx;
        final dy = dst.dy - src.dy;
        final dist = sqrt(dx * dx + dy * dy);
        if (dist == 0) continue;

        final normX = -dy / dist;
        final normY = dx / dist;
        final curvature = min(120.0, dist / 2);
        final control =
        Offset(mid.dx + normX * curvature, mid.dy + normY * curvature);

        final path = ui.Path();
        final color = Color(arc['color'] as int)
            .withOpacity(0.9 * (0.4 + 0.6 * progress));
        paint.color = color;
        paint.strokeWidth = 2.5 + 2.0 * progress;

        final segments = 50;
        final actualSegments = (segments * progress).round();
        for (int i = 0; i <= actualSegments; i++) {
          final t = i / segments;
          final mt = 1 - t;
          final x = mt * mt * src.dx +
              2 * mt * t * control.dx +
              t * t * dst.dx;
          final y = mt * mt * src.dy +
              2 * mt * t * control.dy +
              t * t * dst.dy;

          if (i == 0) {
            path.moveTo(x, y);
          } else {
            path.lineTo(x, y);
          }
        }

        canvas.drawPath(path, paint);

        if (actualSegments > 0) {
          final t = actualSegments / segments;
          final mt = 1 - t;
          final headX = mt * mt * src.dx +
              2 * mt * t * control.dx +
              t * t * dst.dx;
          final headY = mt * mt * src.dy +
              2 * mt * t * control.dy +
              t * t * dst.dy;
          final headPaint = Paint()
            ..style = PaintingStyle.fill
            ..color = color;
          canvas.drawCircle(
              Offset(headX, headY), 3.0 + 2.0 * progress, headPaint);
        }
      } catch (_) {}
    }
  }

  Offset _latLngToOffset(LatLng latLng) {
    return camera.latLngToScreenOffset(latLng);
  }

  bool _isOffScreen(Offset src, Offset dst, Size size) {
    return src.dx < -100 ||
        src.dx > size.width + 100 ||
        src.dy < -100 ||
        src.dy > size.height + 100 ||
        dst.dx < -100 ||
        dst.dx > size.width + 100 ||
        dst.dy < -100 ||
        dst.dy > size.height + 100;
  }

  @override
  bool shouldRepaint(covariant ArcPainter oldDelegate) {
    return oldDelegate.progress != progress || oldDelegate.arcs != arcs;
  }
}