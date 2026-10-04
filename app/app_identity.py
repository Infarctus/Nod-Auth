"""Microsoft Authenticator identity fields extracted from the saved APK."""
import json
import re

from app.state import state_path


def app_version() -> str:
    """Return the APK version name used in Microsoft requests."""
    path = state_path('apk_config.json')
    if not path.exists():
        raise ValueError('apk_config.json is missing; extract it from the APK first')
    config = json.loads(path.read_text())
    version = config.get('version_name')
    if (config.get('package') != 'com.azure.authenticator'
            or not isinstance(version, str)
            or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)+', version)):
        raise ValueError('apk_config.json has no valid Microsoft Authenticator version_name')
    return version
