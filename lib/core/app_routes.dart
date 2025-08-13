import 'package:get/get.dart';
import '../views/home_view.dart';

class AppRoutes {
  static final routes = <GetPage>[
    GetPage(name: '/', page: () => HomeView()),
  ];
}
