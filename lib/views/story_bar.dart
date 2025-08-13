import 'package:flutter/material.dart';
import 'package:get/get.dart';
import '../../models/attack_event.dart';
import '../controller/attack_controller.dart';

class StoryBar extends StatelessWidget {
  final AttackController ctrl = Get.find();
  @override
  Widget build(BuildContext context) {
    return Obx(() {
      final stories = ctrl.storyQueue;
      if (stories.isEmpty) {
        return const SizedBox(
          height: 64,
          child: Center(child: Text('No critical events')),
        );
      }
      return Container(
        height: 88,
        color: Colors.black.withOpacity(0.15),
        child: ListView.builder(
          scrollDirection: Axis.horizontal,
          itemCount: stories.length,
          itemBuilder: (ctx, i) {
            final AttackEvent e = stories[i];
            return Padding(
              padding: const EdgeInsets.all(8.0),
              child: ElevatedButton(
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.transparent,
                  elevation: 0,
                ),
                onPressed: () {
                  ctrl.createArcForEvent(e);
                },
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(Icons.warning, color: _colorForSeverity(e.severity)),
                    const SizedBox(height: 6),
                    Text(
                      e.attackType,
                      style: const TextStyle(fontSize: 12),
                      overflow: TextOverflow.ellipsis,
                    ),
                    const SizedBox(height: 4),
                    Text(
                      e.srcIp,
                      style: TextStyle(fontSize: 11, color: Colors.grey[300]),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                ),
              ),
            );
          },
        ),
      );
    });
  }
  Color _colorForSeverity(String s) {
    switch (s.toLowerCase()) {
      case 'critical': return Colors.redAccent;
      case 'high': return Colors.orangeAccent;
      case 'medium': return Colors.yellowAccent;
      default: return Colors.greenAccent;
    }
  }
}