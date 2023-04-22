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
    INVALID_PLOT_SIGNATURE = 2
    INVALID_POSPACE = 3
    INVALID_HEIGHT = 4
    INVALID_WEIGHT = 5
    INVALID_TOTAL_ITERS = 6

    INVALID_PREV_BLOCK_HASH = 7
    INVALID_PREV_CHALLENGE_SLOT_HASH = 8
    INVALID_SUB_EPOCH_SUMMARY_HASH = 9
    INVALID_CC_EOS_VDF = 10
    INVALID_RC_EOS_VDF = 11
    INVALID_CHALLENGE_SLOT_HASH_RC = 12
    INVALID_DEFICIT = 13
    INVALID_SUB_EPOCH_SUMMARY = 14
    INVALID_NEW_DIFFICULTY = 15
    INVALID_NEW_SUB_SLOT_ITERS = 16
    INVALID_CC_SP_VDF = 17
    INVALID_RC_SP_VDF = 18
    INVALID_CC_SIGNATURE = 19
    INVALID_RC_SIGNATURE = 20
    INVALID_URSB_HASH = 21
    INVALID_CC_IP_VDF = 23
    INVALID_RC_IP_VDF = 23
    INVALID_REWARD_BLOCK_HASH = 24
    NO_OVERFLOWS_IN_FIRST_SUB_SLOT_NEW_EPOCH = 25

    SHOULD_NOT_HAVE_ICC = 26
    INVALID_ICC_VDF = 27
    INVALID_ICC_HASH_CC = 28
    INVALID_ICC_HASH_RC = 29
    INVALID_ICC_EOS_VDF = 30
    INVALID_SP_INDEX = 31
    TOO_MANY_BLOCKS = 32
    INVALID_CC_CHALLENGE = 33

    INCOMPATIBLE_NETWORK_ID = 34
    INVALID_REQUIRED_ITERS = 35

    INTERNAL_PROTOCOL_ERROR = 36
    
    TIMESTAMP_TOO_FAR_IN_FUTURE = 37
    TIMESTAMP_TOO_FAR_IN_PAST = 38
    PAYLOAD_IN_GENESIS_BLOCK = 39
    NO_PAYLOAD = 40
    INVALID_BLOCK_HASH = 41
    INVALID_PARENT_HASH = 42
    INVALID_PREV_RANDAO = 43
    INVALID_BLOCK_NUMBER = 44
    INVALID_TIMESTAMP = 45
    INVALID_EXTRA_DATA_SIZE = 46
    INVALID_GENESIS_EXTRA_DATA = 47
    INVALID_WITHDRAWALS_COUNT = 48
    INVALID_WITHDRAWAL_INDEX = 49
    INVALID_WITHDRAWAL_VALIDATOR_INDEX = 50
    INVALID_WITHDRAWAL_ADDRESS = 51
    INVALID_WITHDRAWAL_AMOUNT = 52
    WITHDRAWAL_ADDRESS_COLLISION = 53
    
    EXECUTION_INVALID_PAYLOAD = 54
    EXECUTION_SYNCING = 56
    EXECUTION_SIDECHAIN = 56


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
