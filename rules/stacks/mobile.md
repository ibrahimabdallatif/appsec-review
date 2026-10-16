---
detect:
  - "package.json with react-native or expo"
  - "pubspec.yaml (Flutter)"
  - "android/ with AndroidManifest.xml, or an Xcode project, Podfile or Package.swift for an iOS app"
---

# Stack: mobile apps (React Native, Expo, Flutter, native Android and iOS)

Use with `client-side.md` (its "Mobile apps" section) and the category files. Map findings to OWASP MASVS 2.1
(STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, RESILIENCE, PRIVACY), a MASWE 1.0 id when one fits, MASTG 2.0
for the test, and the Mobile Top 10:2024 id (M1–M10). Native OAuth also maps to RFC 8252.

## Entry points
- Screens and navigation (React Navigation, Expo Router, Flutter routes, activities and view controllers), deep
  links and universal or app links (`scheme` in `app.json`, intent filters, associated domains), push notification
  handlers, WebViews and their message bridges, background tasks, and the API client with its token handling.

## Storage
- React Native/Expo: `AsyncStorage`, MMKV without encryption, `redux-persist` or `zustand/persist` holding tokens or
  sensitive data; use `expo-secure-store` or `react-native-keychain`. Flutter: `shared_preferences` versus
  `flutter_secure_storage`. Android: `SharedPreferences` versus EncryptedSharedPreferences or the Keystore. iOS:
  `UserDefaults` versus the Keychain with a suitable `kSecAttrAccessible` (`WhenUnlockedThisDeviceOnly`).
- `android:allowBackup="true"` or missing backup rules for app data with tokens.

## Network
- Android: `android:usesCleartextTraffic="true"`, `network_security_config.xml` with `cleartextTrafficPermitted`
  or `<certificates src="user"/>` outside `debug-overrides`. iOS: `NSAppTransportSecurity` exceptions
  (`NSAllowsArbitraryLoads`, per-domain exceptions).
- Custom `TrustManager`/`HostnameVerifier` (Android), `URLSessionDelegate` that accepts any challenge (iOS),
  Flutter `badCertificateCallback` returning true, React Native fetch patched to skip verification.
- Certificate or public-key pinning for banking and payment apps (`react-native-ssl-pinning`, TrustKit, Network
  Security Config `<pin-set>`), with a backup pin and an expiry plan.

## Platform interaction
- Android: exported components (`android:exported="true"`) without permissions, implicit intents carrying
  sensitive data, `PendingIntent` without `FLAG_IMMUTABLE`, content providers with broad `grantUriPermissions`.
- Deep links: parameters that trigger actions (payments, OTP, login) or navigation to sensitive screens without
  re-authentication or validation; custom schemes used for OAuth redirects instead of verified https links.
- WebView (`react-native-webview`, `webview_flutter`, `WebView`, `WKWebView`): JavaScript enabled on remote
  content, `originWhitelist={['*']}`, `allowFileAccess`/`allowUniversalAccessFromFileURLs`,
  `addJavascriptInterface` or `injectedJavaScript` bridges reachable by remote pages, `onMessage` without origin
  checks, `mixedContentMode="always"`.
- Android overlays: sensitive screens should set `filterTouchesWhenObscured` so a drawn-over window cannot
  capture the tap. (MASVS-PLATFORM)

## Cryptography
- Hardcoded keys, `SecretKeySpec` from a string, Flutter `encrypt` with a key in source, static IVs, ECB, and
  `Math.random` / `dart:math` `Random` / `java.util.Random` for keys or tokens. Prefer `KeyGenerator` or
  `SecKey` keys that are not exportable, or the checks in `cryptography-data-protection.md`. (MASVS-CRYPTO, M10)

## Privacy
- Permissions in `AndroidManifest.xml`, `Info.plist` usage strings and Flutter permission plugins that the
  feature does not use (contacts, SMS, fine location, camera, microphone, photo library). Analytics and crash
  SDKs (`Firebase`, `Sentry`, advertising SDKs) initialised with card data, tokens or a stable device id
  (`Settings.Secure.ANDROID_ID`, `AdvertisingIdClient`, `ASIdentifierManager`). (MASVS-PRIVACY, M6)

## Authentication and resilience
- OAuth (RFC 8252): `ASWebAuthenticationSession`, Chrome Custom Tabs or `flutter_web_auth` / `url_launcher`
  to the system browser. Flag an embedded WebView login, a custom-scheme redirect that receives the token, and
  a missing PKCE verifier.
- Biometrics (`expo-local-authentication`, `react-native-biometrics`, `local_auth`, `BiometricPrompt`,
  `LAContext`): success must unlock a Keystore or Keychain key bound to biometric authentication, not set a flag.
- Sensitive screens: `FLAG_SECURE` or `expo-screen-capture`, blur on app switch, no OTP or card data in the
  clipboard or in notifications on the lock screen.
- Release builds: `android:debuggable` off, Hermes or ProGuard/R8 enabled, debug menus and dev servers removed,
  Flipper and React Native dev tools excluded.
- App attestation (Play Integrity, App Attest/DeviceCheck) results verified on the server, not trusted in the app.

## Configuration and updates
- `minSdkVersion` / `minSdk` and `IPHONEOS_DEPLOYMENT_TARGET` left on an OS version that no longer receives
  security patches, and no forced-update check after a critical fix. (MASVS-CODE-1, MASVS-CODE-2)
- Secrets in `app.json`/`app.config.*` `extra`, `EXPO_PUBLIC_*`, `google-services.json` with server keys,
  `Info.plist`, `strings.xml`, `BuildConfig` fields or Flutter `--dart-define`: anything there is extractable.
- Expo Updates or CodePush: code signing configured (`updates.codeSigningCertificate`), update URL over https,
  channels restricted.

## Dependencies
- Outdated React Native, Expo SDK past support, Flutter plugins with advisories, native SDKs (analytics, ads) that
  collect personal data; `Podfile.lock` and Gradle lock or verification metadata committed.
