#include "include/lazysodium/lazysodium_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "lazysodium_plugin.h"

void LazysodiumPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  lazysodium::LazysodiumPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
