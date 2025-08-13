import 'package:get/get.dart';
import '../controller/attack_controller.dart';

class AppBindings extends Bindings {
  @override
  void dependencies() {
    Get.put(AttackController(), permanent: true);
  }
}
