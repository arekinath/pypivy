from enum import Enum, IntFlag

class SCardScope(Enum):
    """Smartcard reader scope used with PCSC."""
    USER = 0
    TERMINAL = 1
    SYSTEM = 2
    GLOBAL = 3
    INVALID = 5

class Algorithm(Enum):
    """PIV algorithm options"""
    DES3    = 0x03
    AES128  = 0x08
    AES192  = 0x0A
    AES256  = 0x0C
    RSA1024 = 0x06
    RSA2048 = 0x07
    ECCP256 = 0x11
    ECCP384 = 0x14

class AuthMethod(Enum):
    """Possible methods by which to authenticate to a PIV token."""
    PIN         = 0x80
    GLOBAL_PIN  = 0x00
    PUK         = 0x81

class SlotId(Enum):
    """All possible PIV slots which can store certificates."""
    PIV_AUTH = 0x9A
    ADMIN = 0x9B
    SIGNATURE = 0x9C
    KEY_MGMT = 0x9D
    CARD_AUTH = 0x9E
    YK_ATTESTATION = 0xF9
    RETIRED_1 = 0x82
    RETIRED_2 = 0x83
    RETIRED_3 = 0x84
    RETIRED_4 = 0x85
    RETIRED_5 = 0x86
    RETIRED_6 = 0x87
    RETIRED_7 = 0x88
    RETIRED_8 = 0x89
    RETIRED_9 = 0x8a
    RETIRED_10 = 0x8b
    RETIRED_11 = 0x8c
    RETIRED_12 = 0x8d
    RETIRED_13 = 0x8e
    RETIRED_14 = 0x8f
    RETIRED_15 = 0x90
    RETIRED_16 = 0x91
    RETIRED_17 = 0x92
    RETIRED_18 = 0x93
    RETIRED_19 = 0x94
    RETIRED_20 = 0x95

class KeyType(Enum):
    """Type of a PublicKey object."""
    RSA = 0
    DSA = 1
    ECDSA = 2
    ED25519 = 3
    UNSPEC = 14

class DigestType(Enum):
    """Algorithm used for calculating a digest (hash) of data."""
    MD5 = 0
    SHA1 = 1
    SHA256 = 2
    SHA384 = 3
    SHA512 = 4

class FingerprintType(Enum):
    """Type of SSH key fingerprint."""
    DEFAULT = 0
    HEX = 1
    BASE64 = 2
    BUBBLEBABBLE = 3
    RANDOMART = 4

class FascnOC(Enum):
    """
    The FASC-N Organizational Category field (OC).
    """
    FEDERAL = 0
    STATE = 1
    COMMERCIAL = 2
    FOREIGN = 3

class FascnPOA(Enum):
    """
    The FASC-N Person-Org Association Type field (POA).
    """
    EMPLOYEE = 0
    CIVIL = 1
    EXECUTIVE = 2
    UNIFORMED = 3
    CONTRACTOR = 4
    AFFILIATE = 5
    BENEFICIARY = 6

class SlotAuth(IntFlag):
    UNKNOWN = 0
    PIN = 1
    TOUCH = 2

class LibSSHErrorCode(Enum):
    """
    Error codes returned by libssh functions.
    """
    SUCCESS = 0
    INTERNAL_ERROR = -1
    ALLOC_FAIL = -2
    MESSAGE_INCOMPLETE = -3
    INVALID_FORMAT = -4
    BIGNUM_IS_NEGATIVE = -5
    STRING_TOO_LARGE = -6
    BIGNUM_TOO_LARGE = -7
    ECPOINT_TOO_LARGE = -8
    NO_BUFFER_SPACE = -9
    INVALID_ARGUMENT = -10
    KEY_BITS_MISMATCH = -11
    EC_CURVE_INVALID = -12
    KEY_TYPE_MISMATCH = -13
    KEY_TYPE_UNKNOWN = -14
    EC_CURVE_MISMATCH = -15
    EXPECTED_CERT = -16
    KEY_LACKS_CERTBLOB = -17
    KEY_CERT_UNKNOWN_TYPE = -18
    KEY_CERT_INVALID_SIGN_KEY = -19
    KEY_INVALID_EC_VALUE = -20
    SIGNATURE_INVALID = -21
    LIBCRYPTO_ERROR = -22
    UNEXPECTED_TRAILING_DATA = -23
    SYSTEM_ERROR = -24
    KEY_CERT_INVALID = -25
    AGENT_COMMUNICATION = -26
    AGENT_FAILURE = -27
    DH_GEX_OUT_OF_RANGE = -28
    DISCONNECTED = -29
    MAC_INVALID = -30
    NO_CIPHER_ALG_MATCH = -31
    NO_MAC_ALG_MATCH = -32
    NO_COMPRESS_ALG_MATCH = -33
    NO_KEX_ALG_MATCH = -34
    NO_HOSTKEY_ALG_MATCH = -35
    NO_HOSTKEY_LOADED = -36
    PROTOCOL_MISMATCH = -37
    NO_PROTOCOL_VERSION = -38
    NEED_REKEY = -39
    PASSPHRASE_TOO_SHORT = -40
    FILE_CHANGED = -41
    KEY_UNKNOWN_CIPHER = -42
    KEY_WRONG_PASSPHRASE = -43
    KEY_BAD_PERMISSIONS = -44
    KEY_CERT_MISMATCH = -45
    KEY_NOT_FOUND = -46
    AGENT_NOT_PRESENT = -47
    AGENT_NO_IDENTITIES = -48
    BUFFER_READ_ONLY = -49
    KRL_BAD_MAGIC = -50
    KEY_REVOKED = -51
    CONN_CLOSED = -52
    CONN_TIMEOUT = -53
    CONN_CORRUPT = -54
    PROTOCOL_ERROR = -55
    KEY_LENGTH = -56
    NUMBER_TOO_LARGE = -57
    SIGN_ALG_UNSUPPORTED = -58
    FEATURE_UNSUPPORTED = -59
    DEVICE_NOT_FOUND = -60

class CAEboxType(Enum):
    PIN = 0
    OLD_PIN = 1
    PUK = 2
    KEY_BACKUP = 3
    ADMIN_KEY = 4

class CACertType(Enum):
    TOKEN = 1
    INTERMEDIATE = 2
    OTHER = 3

class CATokenTplFlag(IntFlag):
    PUK_RAND = (1<<0)
    ADMIN_KEY_RAND = (1<<1)
    ADMIN_KEY_PINFO = (1<<2)
    SIGN_CHUID = (1<<3)
    PINFO = (1<<4)

class CACertTplFlag(IntFlag):
    SELF_SIGNED = (1<<0)
    ALLOW_REQS = (1<<1)
    COPY_DN = (1<<2)
    COPY_KP = (1<<3)
    COPY_SAN = (1<<4)
    COPY_OTHER_EXTS = (1<<5)
    KEY_BACKUP = (1<<6)
    HOST_KEYGEN = (1<<7)

class EboxConfigType(Enum):
    PRIMARY = 0x01
    RECOVERY = 0x02

class EboxType(Enum):
    TEMPLATE = 0x01
    KEY = 0x02
    STREAM = 0x03

class EboxChalType(Enum):
    RECOVERY = 1
    VERIFY_AUDIT = 2

class CardcapType(Enum):
    FS = 0x01
    JAVACARD = 0x02
    MULTOS = 0x03
    JAVACARD_FS = 0x04

class CardcapDataModel(Enum):
    PIV = 0x10
