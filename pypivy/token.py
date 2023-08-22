from __future__ import annotations
from pypivy.pivy_ctypes import *

import pypivy
from pypivy.enums import *
from pypivy.errf import Errf
from pypivy.libssh import PublicKey
from pypivy.token_meta import Chuid, Fascn
from pypivy.ca import Cert

class Token:
    """
    Represents a PIV token available on the system, and allows retrieving
    information about it.

    May also be used with the `Transaction` class to begin performing
    operations on the token.
    """
    def __init__(self, set: TokenSet, ptr: c_void_p):
        self._set = set
        self._ptr = ptr
        self._txn = None
    def __repr__(self):
        s = '<Token(reader = "' + self.reader_name + '", guid = "' + self.guid_hex + '"'
        if self.is_ykpiv:
            s = s + ', serial = ' + str(self.ykpiv_serial)
        s = s + ')>'
        return s
    @property
    def valid(self) -> bool:
        """
        Returns True if the token object is valid and useable (i.e. has not
        been freed in C code)
        """
        return self._set.valid
    @property
    def reader_name(self) -> str:
        """
        Retrieves the PCSC 'reader' name that this token is located in.
        """
        return libpivy.piv_token_rdrname(self._ptr).decode('utf-8')
    @property
    def chuid(self) -> Chuid | None:
        """
        Returns a reference to the token's CHUID (cardholder/user identification)
        object.
        """
        ptr = libpivy.piv_token_chuid(self._ptr)
        if ptr:
            return Chuid(owner = self, ptr = ptr)
        else:
            return None
    @property
    def fascn(self) -> Fascn | None:
        """
        Returns a reference to the token's FASC-N, if any.
        """
        ptr = libpivy.piv_token_fascn(self._ptr)
        if ptr:
            return Fascn(owner = self, ptr = ptr)
        else:
            return None
    @property
    def guid_hex(self) -> str:
        """
        The token's GUID, as a hex string.
        """
        return libpivy.piv_token_guid_hex(self._ptr).decode('ascii')
    @property
    def algorithms(self) -> list[Algorithm]:
        """
        List of algorithms the token supports. Few tokens implement this list,
        and most that do will return only VCI/Secure Messaging algorithms.
        """
        n = libpivy.piv_token_nalgs(self._ptr)
        l = []
        for i in range(0, n):
            algid = libpivy.piv_token_alg(self._ptr, i)
            l.append(Algorithm(value = algid))
        return l
    @property
    def default_auth(self) -> AuthMethod:
        """
        The 'default' user authentication method for this token, used to
        determine whether a device global PIN or PIV application specific PIN
        is more preferable.
        """
        v = libpivy.piv_token_default_auth(self._ptr)
        return AuthMethod(value = v)
    def has_auth(self, method: AuthMethod) -> bool:
        """
        Checks to see if the token supports a particular user authentication
        method.
        """
        r = libpivy.piv_token_has_auth(self._ptr, method.value)
        return (r == 1)
    @property
    def keyhistory_oncard(self) -> int:
        return libpivy.piv_token_keyhistory_oncard(self._ptr)
    @property
    def keyhistory_offcard(self) -> int:
        return libpivy.piv_token_keyhistory_offcard(self._ptr)
    @property
    def offcard_url(self) -> Optional[str]:
        s = libpivy.piv_token_offcard_url(self._ptr)
        if s:
            return ptr.decode('utf-8')
        else:
            return None
    @property
    def app_label(self) -> Optional[str]:
        """
        The contents of the RTS 'application label' field. If set, contains
        a user-readable string identifying the firmware or applet running on
        the token.
        """
        s = libpivy.piv_token_app_label(self._ptr)
        if s:
            return s.decode('utf-8')
        else:
            return None
    @property
    def app_uri(self) -> Optional[str]:
        """
        The contents of the RTS 'application URI' field. If set, contains
        a URI or URL giving further information about the firmware or applet
        running on the token.
        """
        s = libpivy.piv_token_app_uri(self._ptr)
        if s:
            return s.decode('utf-8')
        else:
            return None
    @property
    def is_ykpiv(self) -> bool:
        """
        Identifies whether this token implements YubicoPIV extensions.
        """
        v = libpivy.piv_token_is_ykpiv(self._ptr)
        return (v == 1)
    @property
    def ykpiv_version(self) -> tuple[int, int, int]:
        """
        The version of YubicoPIV extensions supported by this token.
        """
        ptr = libpivy.ykpiv_token_version(self._ptr)
        return (ptr[0], ptr[1], ptr[2])
    @property
    def ykpiv_serial(self) -> int:
        """
        The serial number of a YubiKey device.
        """
        return libpivy.ykpiv_token_serial(self._ptr)
    @property
    def slots(self) -> Iterator[TokenSlot]:
        """
        An iterator over all the currently cached slots on this token. Note that
        a fresh token returned by `enumerate()` or `find()` will generally have
        nothing in this list. Calling e.g. `read_cert()` in a Transaction will
        retrieve the information to populate it.
        """
        return TokenSlotIterator(token = self, token_ptr = self._ptr)
    def slot(self, id: SlotId) -> Optional[TokenSlot]:
        """
        Retrieves a specific slot by its ID, if information has been cached
        about that slot.
        """
        ptr = libpivy.piv_get_slot(self._ptr, id.value)
        if ptr:
            return TokenSlot(token = self, ptr = ptr)
        else:
            return None
    @property
    def current_transaction(self) -> Optional[Transaction]:
        """
        The current transaction in progress for this token, if any.
        """
        return self._txn
    def _take_txn(self, new_txn: Transaction) -> c_void_p:
        if self._txn:
            raise AlreadyTransactedException(self)
        self._txn = new_txn
        return self._ptr
    def _end_txn(self, txn: Transaction):
        if self._txn != txn:
            raise Exception('txn mismatch!')
        self._txn = None
    def begin_transaction(self) -> Transaction:
        """
        Begins a new transaction on this token, allowing use of commands
        (e.g. reading certificates or signing data).

        :raises AlreadyTransactedException: a Transaction for this Token is
            already in progress
        :raises IOError: failed to communicate with the device to begin the
            transaction. caused by a PCSCError.
        """
        return Transaction(self)

class AlreadyTransactedException(Exception):
    """
    Raised when a Transaction is already in progress for a given Token and
    an attempt has been made to create a new Transaction for the same Token.
    """
    def __init__(self, token: Token):
        self._token = token
        super().__init__('Transaction already in progress for token ' + repr(token))
    @property
    def token(self) -> Token:
        return self._token

class TransactionEndedException(Exception):
    """
    Raised when I/O methods are called on a Transaction after that Transaction
    has been ended.
    """
    def __init__(self, transaction: Transaction):
        self._txn = transaction
        super().__init__('Transaction already ended')
    @property
    def transaction(self) -> Transaction:
        return self._txn

class Transaction:
    def __init__(self, token: Token):
        self._token = token
        self._ptr = token._take_txn(self)
        self._retries = None
        err = libpivy.piv_txn_begin(self._ptr)
        if err:
            token._end_txn(self)
            raise Errf(err)
    def __del__(self):
        if self._token:
            self.end()
    def end(self):
        if not self._token:
            raise TransactionEndedException(self)
        libpivy.piv_txn_end(self._ptr)
        self._ptr = None
        self._token._end_txn(self)
        self._token = None
    def select(self):
        err = libpivy.piv_select(self._ptr)
        if err:
            raise Errf(err)
    def read_all_certs(self):
        err = libpivy.piv_read_all_certs(self._ptr)
        if err:
            raise Errf(err)
    def read_cert(self, id: SlotId):
        err = libpivy.piv_read_cert(self._ptr, id.value)
        if err:
            raise Errf(err)
    def read_cardcap(self) -> Cardcap:
        ptr = c_void_p()
        err = libpivy.piv_read_cardcap(self._ptr, byref(ptr))
        if err:
            raise Errf(err)
        return pypivy.Cardcap(ptr = ptr)
    def read_pinfo(self) -> PrintedInfo:
        ptr = c_void_p()
        err = libpivy.piv_read_pinfo(self._ptr, byref(ptr))
        if err:
            raise Errf(err)
        return pypivy.PrintedInfo(ptr = ptr)
    def write_cardcap(self, obj: Cardcap):
        if not isinstance(obj, pypivy.Cardcap):
            raise TypeError('obj must be a Cardcap instance')
        err = libpivy.piv_write_cardcap(self._ptr, obj._ptr)
        if err:
            raise Errf(err)
    def write_chuid(self, obj: Chuid):
        if not isinstance(obj, pypivy.Chuid):
            raise TypeError('obj must be a Chuid instance')
        err = libpivy.piv_write_chuid(self._ptr, obj._ptr)
        if err:
            raise Errf(err)
    def write_pinfo(self, obj: PrintedInfo):
        if not isinstance(obj, pypivy.PrintedInfo):
            raise TypeError('obj must be a PrintedInfo instance')
        err = libpivy.piv_write_pinfo(self._ptr, obj._ptr)
        if err:
            raise Errf(err)
    def auth_admin(self, algorithm: Algorithm, key_or_hex: str | bytes):
        if isinstance(key_or_hex, str):
            key = bytes.from_hex(key_or_hex)
        else:
            key = key_or_hex
        err = libpivy.piv_auth_admin(self._ptr, key, len(key), algorithm.value)
        if err:
            raise Errf(err)
    @property
    def attempts_remaining(self) -> Optional[int]:
        """
        Returns the number of PIN attempts remaining after the most recent
        verify_pin() or get_pin_attempts() operation, if any.
        """
        return self._retries
    def get_pin_attempts(self, method: AuthMethod) -> int:
        retries = c_uint(0)
        err = libpivy.piv_verify_pin(self._ptr, method.value, None, byref(retries), 0)
        self._retries = retries.value
        if err:
            raise Errf(err)
        return self._retries
    def check_cached_pin(self, method: AuthMethod) -> bool:
        err = libpivy.piv_verify_pin(self._ptr, method.value, None, None, 1)
        if err:
            libpivy.errf_free(err)
            return False
        return True
    def verify_pin(self, method: AuthMethod, pin: str, min_retries: int = 1, use_cached: bool = True):
        retries = c_uint(min_retries)
        err = libpivy.piv_verify_pin(self._ptr, method.value, pin.encode('ascii'), byref(retries), 1 if use_cached else 0)
        self._retries = retries.value
        if err:
            raise Errf(err)
    def clear_pin(self, method: AuthMethod):
        err = libpivy.piv_clear_pin(self._ptr, method.value)
        if err:
            raise Errf(err)
    def auth_key(self, slot: TokenSlot, pubkey: PublicKey):
        if not isinstance(slot, TokenSlot):
            raise TypeError('"slot" must be a TokenSlot')
        if not isinstance(pubkey, PublicKey):
            raise TypeError('"pubkey" must be a PublicKey')
        err = libpivy.piv_auth_key(self._ptr, slot._ptr, pubkey._ptr)
        if err:
            raise Errf(err)
    def open_box(self, slot: TokenSlot, box: Box):
        if not isinstance(slot, TokenSlot):
            raise TypeError('"slot" must be a TokenSlot')
        if not isinstance(box, pypivy.Box):
            raise TypeError('"box" must be a Box')
        err = libpivy.piv_box_open(self._ptr, slot._ptr, box._ptr)
        if err:
            raise Errf(err)

class TokenSlotIterator:
    def __init__(self, token: Token, token_ptr: c_void_p, slot_ptr: c_void_p = None):
        self._token = token
        self._tokptr = token_ptr
        self._ptr = slot_ptr
        if not slot_ptr:
            self._ptr = libpivy.piv_slot_next(self._tokptr, c_void_p())
    def __iter__(self):
        return self
    def __next__(self):
        ptr = self._ptr
        if ptr:
            self._ptr = libpivy.piv_slot_next(self._tokptr, ptr)
            return TokenSlot(token = self._token, ptr = ptr)
        else:
            raise StopIteration

class TokenSlot:
    def __init__(self, token: Token, ptr: c_void_p):
        self._token = token
        self._ptr = ptr
    def __repr__(self):
        return '<TokenSlot(id = ' + self.id.name + ', algorithm = ' + \
            self.algorithm.name + ', subj = ' + self.cert_subject_dn + ')>'
    @property
    def auth_required(self) -> SlotAuth:
        v = libpivy.piv_slot_get_auth(self._token._ptr, self._ptr)
        return SlotAuth(value = v)
    @property
    def id(self) -> SlotId:
        v = libpivy.piv_slot_id(self._ptr)
        return SlotId(value = v)
    @property
    def algorithm(self) -> Algorithm:
        v = libpivy.piv_slot_alg(self._ptr)
        return Algorithm(value = v)
    @property
    def cert_subject_dn(self) -> str:
        return libpivy.piv_slot_subject(self._ptr).decode('utf-8')
    @property
    def cert_issuer_dn(self) -> str:
        return libpivy.piv_slot_issuer(self._ptr).decode('utf-8')
    @property
    def cert_serial_hex(self) -> str:
        return libpivy.piv_slot_serial_hex(self._ptr).decode('ascii')
    @property
    def cert(self) -> Cert:
        ptr = libpivy.piv_slot_cert(self._ptr)
        return Cert(owner = self, ptr = ptr)
    @property
    def cert_der(self) -> bytes:
        return self.cert.to_der()
    @property
    def public_key(self) -> Optional[PublicKey]:
        ptr = libpivy.piv_slot_pubkey(self._ptr)
        if ptr:
            return PublicKey(owner = self._token, ptr = ptr)
        else:
            return None

from pypivy.context import TokenSet
