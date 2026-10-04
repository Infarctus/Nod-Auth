# Third-party notices

Nod Auth's own code is licensed under Apache-2.0; see [LICENSE](LICENSE).
Dependencies and protocol references retain their own licenses. This file
records direct dependencies and known references, not a complete inventory of
everything in an Android APK or container image.

## Protocol references and repository tooling

- [microG GmsCore](https://github.com/microg/GmsCore), Apache-2.0:
  `app/fcm.py` and `app/mcs.py` reimplement check-in and messaging processes
  described by that project. The Apache-2.0 text is included in `LICENSE`.
- [Chromium MCS protocol definitions](https://github.com/chromium/chromium/blob/main/google_apis/gcm/protocol/mcs.proto),
  BSD-3-Clause: referenced by `app/mcs.py`. The upstream copyright notice and
  license are included in [licenses/Chromium-BSD-3-Clause.txt](licenses/Chromium-BSD-3-Clause.txt).
- [Gradle](https://github.com/gradle/gradle), Apache-2.0: the wrapper scripts and
  JAR are upstream tooling. The original script copyright/license headers are
  retained; the Apache-2.0 text is included in `LICENSE`.

## Direct runtime dependencies

| Component | License | Upstream |
| --- | --- | --- |
| curl-cffi | MIT | https://github.com/lexiforest/curl_cffi |
| tls-client | MIT | https://github.com/FlorianREGAZ/Python-Tls-Client |
| typing-extensions | PSF-2.0 | https://github.com/python/typing_extensions |
| discord.py | MIT | https://github.com/Rapptz/discord.py |
| certifi | MPL-2.0 | https://github.com/certifi/python-certifi |
| CFFI | MIT | https://github.com/python-cffi/cffi |
| pycparser | BSD-3-Clause | https://github.com/eliben/pycparser |
| Chaquopy | MIT | https://github.com/chaquo/chaquopy |
| Python runtime | PSF-2.0 and bundled component licenses | https://docs.python.org/3/license.html |
| AndroidX / Jetpack Compose | Apache-2.0 | https://android.googlesource.com/platform/frameworks/support/ |
| ZXing Android Embedded | Apache-2.0 | https://github.com/journeyapps/zxing-android-embedded |
| OkHttp | Apache-2.0 | https://github.com/square/okhttp |

Versions are pinned in `requirements.txt`, `android-app/app/build.gradle.kts`,
and `android-app/build.gradle.kts`. The local CFFI wheel builder carries the
upstream CFFI license into the wheel. Native libraries, transitive dependencies,
and the Python runtime can have additional notices and obligations.

## Binary distribution

The Android build includes this file, the project license, the privacy document,
and `licenses/` under `assets/legal/`, and merges rather than drops dependency
`META-INF/AL2.0` and `META-INF/LGPL2.1` files. Container builds include the same
documents under `/app/legal/`.

These steps alone do not establish complete binary license compliance. Before
publishing a built APK or image, inventory its actual bundled components, retain
their copyright/license/NOTICE texts, and satisfy any source availability
requirements (including the MPL-2.0 requirements for certifi). Build tooling can
omit metadata even when upstream wheels or JARs supply it. A license-name table
or an upstream link is not a substitute for required license text or notices.

Microsoft Authenticator is proprietary and is not distributed by this project.
Its package name, certificate fingerprints, and Firebase configuration are read
from an APK supplied locally by the user. Their visibility in that APK does not
grant permission to reuse the identity or access associated services.
