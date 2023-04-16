from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any, List


class Err(Enum):
    # temporary errors. Don't blacklist
    INVALID_PROTOCOL_MESSAGE = -1  # We WILL ban for a protocol violation.
    SELF_CONNECTION = -2
    INVALID_HANDSHAKE = -3

    UNKNOWN = 1

    # permanent errors. Block is un-salvageable garbage.
    INVALID_PLOT_SIGNATURE = 1
    INVALID_POSPACE = 2
    INVALID_HEIGHT = 3
    INVALID_WEIGHT = 4
    INVALID_TOTAL_ITERS = 5

    INVALID_PREV_BLOCK_HASH = 6
    INVALID_PREV_CHALLENGE_SLOT_HASH = 7
    INVALID_SUB_EPOCH_SUMMARY_HASH = 8
    INVALID_CC_EOS_VDF = 9
    INVALID_RC_EOS_VDF = 10
    INVALID_CHALLENGE_SLOT_HASH_RC = 11
    INVALID_DEFICIT = 12
    INVALID_SUB_EPOCH_SUMMARY = 13
    INVALID_NEW_DIFFICULTY = 14
    INVALID_NEW_SUB_SLOT_ITERS = 15
    INVALID_CC_SP_VDF = 15
    INVALID_RC_SP_VDF = 17
    INVALID_CC_SIGNATURE = 18
    INVALID_RC_SIGNATURE = 19
    INVALID_URSB_HASH = 20
    INVALID_CC_IP_VDF = 21
    INVALID_RC_IP_VDF = 22
    INVALID_REWARD_BLOCK_HASH = 23
    NO_OVERFLOWS_IN_FIRST_SUB_SLOT_NEW_EPOCH = 24

    SHOULD_NOT_HAVE_ICC = 25
    INVALID_ICC_VDF = 26
    INVALID_ICC_HASH_CC = 27
    INVALID_ICC_HASH_RC = 28
    INVALID_ICC_EOS_VDF = 29
    INVALID_SP_INDEX = 30
    TOO_MANY_BLOCKS = 31
    INVALID_CC_CHALLENGE = 32

    INCOMPATIBLE_NETWORK_ID = 33
    INVALID_REQUIRED_ITERS = 34

    INTERNAL_PROTOCOL_ERROR = 35
    
    PAYLOAD_INVALID = 36
    PAYLOAD_SIDECHAIN = 37
    PAYLOAD_INVALID_BLOCK_HASH = 38
    PAYLOAD_INVALID_TERMINAL_BLOCK = 39
    PAYLOAD_HASH_MISMATCH = 40
    PAYLOAD_IN_GENESIS_BLOCK = 41
    NO_PAYLOAD = 42


class ValidationError(Exception):
    def __init__(self, code: Err, error_msg: str = ""):
        super().__init__(f"Error code: {code.name} {error_msg}")
        self.code = code
        self.error_msg = error_msg


class ConsensusError(Exception):
    def __init__(self, code: Err, errors: List[Any] = []):
        super().__init__(f"Error code: {code.name} {errors}")
        self.errors = errors


class ProtocolError(Exception):
    def __init__(self, code: Err, errors: List[Any] = []):
        super().__init__(f"Error code: {code.name} {errors}")
        self.code = code
        self.errors = errors


##
#  Keychain errors
##


class KeychainException(Exception):
    pass


class KeychainKeyDataMismatch(KeychainException):
    def __init__(self, data_type: str):
        super().__init__(f"KeyData mismatch for: {data_type}")


class KeychainIsLocked(KeychainException):
    pass


class KeychainSecretsMissing(KeychainException):
    pass


class KeychainCurrentPassphraseIsInvalid(KeychainException):
    def __init__(self) -> None:
        super().__init__("Invalid current passphrase")


class KeychainMaxUnlockAttempts(KeychainException):
    def __init__(self) -> None:
        super().__init__("maximum passphrase attempts reached")


class KeychainNotSet(KeychainException):
    pass


class KeychainIsEmpty(KeychainException):
    pass


class KeychainKeyNotFound(KeychainException):
    pass


class KeychainMalformedRequest(KeychainException):
    pass


class KeychainMalformedResponse(KeychainException):
    pass


class KeychainProxyConnectionFailure(KeychainException):
    def __init__(self) -> None:
        super().__init__("Failed to connect to keychain service")


class KeychainLockTimeout(KeychainException):
    pass


class KeychainProxyConnectionTimeout(KeychainException):
    def __init__(self) -> None:
        super().__init__("Could not reconnect to keychain service in 30 seconds.")


class KeychainUserNotFound(KeychainException):
    def __init__(self, service: str, user: str) -> None:
        super().__init__(f"user {user!r} not found for service {service!r}")


class KeychainFingerprintError(KeychainException):
    def __init__(self, fingerprint: int, message: str) -> None:
        self.fingerprint = fingerprint
        super().__init__(f"fingerprint {str(fingerprint)!r} {message}")


class KeychainFingerprintNotFound(KeychainFingerprintError):
    def __init__(self, fingerprint: int) -> None:
        super().__init__(fingerprint, "not found")


class KeychainFingerprintExists(KeychainFingerprintError):
    def __init__(self, fingerprint: int) -> None:
        super().__init__(fingerprint, "already exists")


class KeychainLabelError(KeychainException):
    def __init__(self, label: str, error: str):
        super().__init__(error)
        self.label = label


class KeychainLabelInvalid(KeychainLabelError):
    pass


class KeychainLabelExists(KeychainLabelError):
    def __init__(self, label: str, fingerprint: int) -> None:
        super().__init__(label, f"label {label!r} already exists for fingerprint {str(fingerprint)!r}")
        self.fingerprint = fingerprint


##
#  Miscellaneous errors
##


class InvalidPathError(Exception):
    def __init__(self, path: Path, error_message: str):
        super().__init__(f"{error_message}: {str(path)!r}")
        self.path = path
