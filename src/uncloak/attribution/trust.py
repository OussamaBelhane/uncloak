"""
Authenticode Digital Signature Verification via Win32 wintrust.dll WinVerifyTrust.
Verifies binary integrity and code-signing identity without external binaries.
"""

from __future__ import annotations

import ctypes
import os
import sys

# WinVerifyTrust Action GUID: WINTRUST_ACTION_GENERIC_VERIFY_V2
# {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B,
    0xCD44,
    0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_IGNORE = 0


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_ulong),
        ("pcwszFilePath", ctypes.c_wchar_p),
        ("hFile", ctypes.c_void_p),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_ulong),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", ctypes.c_ulong),
        ("fdwRevocationChecks", ctypes.c_ulong),
        ("dwUnionChoice", ctypes.c_ulong),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", ctypes.c_ulong),
        ("hWVTStateData", ctypes.c_void_p),
        ("pwszURLReference", ctypes.c_wchar_p),
        ("dwProvFlags", ctypes.c_ulong),
        ("dwUIContext", ctypes.c_ulong),
    ]


def verify_authenticode(file_path: str) -> tuple[bool, str]:
    """
    Verifies the Authenticode signature of a PE binary via WinVerifyTrust.
    Returns (is_valid_and_trusted, details_or_error_code).
    """
    if not file_path or not os.path.exists(file_path):
        return False, "FILE_NOT_FOUND"

    if sys.platform != "win32":
        # Fallback for Linux testing environments
        return False, "NON_WINDOWS_HOST"

    try:
        wintrust = ctypes.windll.wintrust  # type: ignore[attr-defined]

        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = file_path
        file_info.hFile = None
        file_info.pgKnownSubject = None

        win_data = WINTRUST_DATA()
        win_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        win_data.pPolicyCallbackData = None
        win_data.pSIPClientData = None
        win_data.dwUIChoice = WTD_UI_NONE
        win_data.fdwRevocationChecks = WTD_REVOKE_NONE
        win_data.dwUnionChoice = WTD_CHOICE_FILE
        win_data.pFile = ctypes.pointer(file_info)
        win_data.dwStateAction = WTD_STATEACTION_IGNORE
        win_data.hWVTStateData = None
        win_data.pwszURLReference = None
        win_data.dwProvFlags = 0x00000080  # WTD_CACHE_ONLY_URL_RETRIEVAL
        win_data.dwUIContext = 0

        action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2

        result = wintrust.WinVerifyTrust(
            None,
            ctypes.byref(action_guid),
            ctypes.byref(win_data),
        )

        # 0x00000000 = ERROR_SUCCESS (Signature valid and trusted)
        if result == 0:
            return True, "TRUSTED_AUTHENTICODE"
        elif result == -2146762496:  # 0x800B0100 TRUST_E_NOSIGNATURE
            return False, "NO_SIGNATURE"
        elif result == -2146762486:  # 0x800B010A CERT_E_UNTRUSTEDROOT
            return False, "UNTRUSTED_ROOT"
        elif result == -2146762487:  # 0x800B0109 CERT_E_CHAINING
            return False, "UNTRUSTED_CHAIN"
        else:
            return False, f"FAILED_0x{result & 0xFFFFFFFF:08X}"
    except Exception as exc:
        return False, f"EXCEPTION_{exc}"
