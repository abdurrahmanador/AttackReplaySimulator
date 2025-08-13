import 'dart:convert';
import 'package:web_socket_channel/web_socket_channel.dart';

class WebSocketService {
  final String url;
  late WebSocketChannel _channel;

  WebSocketService(this.url);

  void connect(void Function(Map<String, dynamic>) onMessage) {
    _channel = WebSocketChannel.connect(Uri.parse(url));

    _channel.stream.listen((message) {
      try {
        final data = jsonDecode(message);
        onMessage(data);
      } catch (e) {
        print("WebSocket parse error: $e");
      }
    }, onError: (error) {
      print("WebSocket error: $error");
    }, onDone: () {
      print("WebSocket closed, reconnecting in 5s...");
      Future.delayed(Duration(seconds: 5), () {
        connect(onMessage);
      });
    });
  }

  void send(String msg) {
    _channel.sink.add(msg);
  }

  void dispose() {
    _channel.sink.close();
  }
}