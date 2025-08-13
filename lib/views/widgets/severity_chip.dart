import 'package:flutter/material.dart';

class SeverityChip extends StatelessWidget {
  final String severity;
  const SeverityChip({super.key, required this.severity});

  Color _getColor() {
    switch (severity.toLowerCase()) {
      case 'critical':
        return Colors.red;
      case 'high':
        return Colors.orange;
      case 'medium':
        return Colors.amber;
      default:
        return Colors.green;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Chip(
      label: Text(severity.toUpperCase(),
          style: TextStyle(color: Colors.white)),
      backgroundColor: _getColor(),
    );
  }
}