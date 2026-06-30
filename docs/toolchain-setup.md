# Toolchain setup (Arch Linux)

Building the Lattice Flutter clients for Android needs: a JDK, the Flutter SDK
(already installed at `~/flutter`), the Android SDK + NDK, the Rust Android
targets, and the `cargo-ndk` / `flutter_rust_bridge_codegen` tooling.

On Arch, `sudo pacman` covers the JDK, native/desktop deps, and `adb`. The
Android SDK/NDK are **not** in the official repos, so they install user-local
(no sudo) under `~/Android` — which avoids root-owned SDK permission problems.

## 1. pacman (sudo)

```bash
sudo pacman -S --needed jdk17-openjdk clang cmake ninja pkgconf gtk3 xz unzip wget android-tools android-udev base-devel
sudo archlinux-java set java-17-openjdk
```

- `jdk17-openjdk` — Flutter/AGP require JDK 17 (path `/usr/lib/jvm/java-17-openjdk`).
- `clang cmake ninja pkgconf gtk3` — Flutter **Linux desktop** target (the "Arch" build).
- `android-tools` + `android-udev` — `adb`/`fastboot` and USB device permissions.

## 2. Rust targets + bridge tooling (no sudo)

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
cargo install cargo-ndk flutter_rust_bridge_codegen
```

- `aarch64` is the only ABI real devices need; the others cover 32-bit + emulator.
- `cargo-ndk` cross-compiles `lattice-mobile` to each ABI's `.so`.

## 3. Android SDK + NDK (no sudo)

Current command-line tools build: **14742923** (Android 17 era; verify the latest
at the release notes link below).

```bash
mkdir -p ~/Android/cmdline-tools && cd /tmp
wget https://dl.google.com/android/repository/commandlinetools-linux-14742923_latest.zip
unzip commandlinetools-linux-14742923_latest.zip -d ~/Android/cmdline-tools
mv ~/Android/cmdline-tools/cmdline-tools ~/Android/cmdline-tools/latest

# ~/.bashrc / ~/.zshrc
export ANDROID_HOME=$HOME/Android
export PATH=$PATH:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools

sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0" "ndk;27.2.12479018"
yes | sdkmanager --licenses
```

If a package errors as not found, list and substitute the current version:
`sdkmanager --list | grep -E 'ndk|platforms;android|build-tools'`.

## 4. Wire Flutter up and verify

```bash
flutter config --android-sdk "$ANDROID_HOME" --jdk-dir /usr/lib/jvm/java-17-openjdk
flutter doctor --android-licenses
flutter doctor -v
```

Target state: green checks for **Flutter**, **Android toolchain**, and **Linux
toolchain**. Chrome/Android Studio checks are optional for our workflow.

## Sandbox note

This setup must run on the real Arch machine — Google's SDK/NDK servers
(`dl.google.com`) are outside the Claude Code sandbox network allowlist. The
sandbox can still validate the Rust facade (`cargo check`), `dart analyze`, and
the Linux-desktop run.

## Sources

- [Android SDK command-line tools release notes](https://developer.android.com/tools/releases/cmdline-tools)
- [Command-line tools overview](https://developer.android.com/tools)
