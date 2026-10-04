#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -d /usr/lib/jvm/java-21-openjdk-amd64 ]]; then
    export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
fi
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$PWD/.toolchain/gradle-home}"
build_python="${ANDROID_BUILD_PYTHON:-$PWD/.toolchain/python/cpython-3.13-linux-x86_64-gnu/bin/python3.13}"
if [[ ! -x "$build_python" ]]; then build_python=python3.13; fi
exec ./gradlew "-PbuildPython=$build_python" "${@:-:app:assembleDebug}"
