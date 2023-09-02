#ifndef FLUTTER_PLUGIN_LAZYSODIUM_PLUGIN_H_
#define FLUTTER_PLUGIN_LAZYSODIUM_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace lazysodium {

class LazysodiumPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  LazysodiumPlugin();

  virtual ~LazysodiumPlugin();

  // Disallow copy and assign.
  LazysodiumPlugin(const LazysodiumPlugin&) = delete;
  LazysodiumPlugin& operator=(const LazysodiumPlugin&) = delete;

  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace lazysodium

#endif  // FLUTTER_PLUGIN_LAZYSODIUM_PLUGIN_H_
