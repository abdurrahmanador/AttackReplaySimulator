// lib/views/home_view.dart
import 'package:flutter/material.dart';
import 'package:get/get.dart';
import '../controller/attack_controller.dart';
import 'widgets/attack_card.dart';
import 'story_bar.dart';
import 'map_view.dart';

class HomeView extends StatelessWidget {
  HomeView({Key? key}) : super(key: key);

  final AttackController controller = Get.find();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text("AttackReplay Dashboard"),
      ),
      body: Column(
        children: [
          StoryBar(),

          Expanded(
            child: Row(
              children: [
                Expanded(
                  flex: 3,
                  child: MapView(),
                ),

                Expanded(
                  flex: 2,
                  child: Obx(() {
                    if (controller.events.isEmpty) {
                      return const Center(
                        child: Text("No events yet..."),
                      );
                    }
                    return ListView.builder(
                      itemCount: controller.events.length,
                      itemBuilder: (context, index) {
                        return AttackCard(event: controller.events[index]);
                      },
                    );
                  }),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}