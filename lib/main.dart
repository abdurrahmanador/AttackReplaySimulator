import 'package:flutter/material.dart';
import 'package:get/get.dart';
import 'core/app_bindings.dart';
import 'core/app_routes.dart';

void main() {
  runApp(const AttackReplayApp());
}

class AttackReplayApp extends StatelessWidget {
  const AttackReplayApp({super.key});

  @override
  Widget build(BuildContext context) {
    return GetMaterialApp(
      title: 'AttackReplay',
      initialBinding: AppBindings(),
      getPages: AppRoutes.routes,
      theme: ThemeData.dark(useMaterial3: true),
      debugShowCheckedModeBanner: false,
    );
  }
}
