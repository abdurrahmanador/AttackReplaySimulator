import 'package:flutter/material.dart';
import '../../models/attack_event.dart';
import 'severity_chip.dart';

class AttackCard extends StatelessWidget {
  final AttackEvent event;
  const AttackCard({super.key, required this.event});

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      child: ListTile(
        title: Text(event.attackType,
            style: TextStyle(fontWeight: FontWeight.bold)),
        subtitle: Text(
            "IP: ${event.srcIp}\nTime: ${event.timestamp}\nRaw: ${event.raw}"),
        trailing: SeverityChip(severity: event.severity),
      ),
    );
  }
}