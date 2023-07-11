from __future__ import annotations
from pypivy.pivy_ctypes import *

import pypivy
from pypivy.enums import *
from pypivy.errf import Errf
from pypivy.libssh import PublicKey, SSHBuffer
from pypivy.context import TokenSet

class Box:
    def __init__(self, ptr: Optional[c_void_p] = None):
        if not ptr:
            ptr = libpivy.piv_box_new()
        self._ptr = ptr
    def __del__(self):
        libpivy.piv_box_free(self._ptr)
        self._ptr = None
    def __repr__(self):
        s = '<Box(version = ' + str(self.version)
        if self.has_guidslot:
            s += ', guid = ' + self.guid + ', slot = ' + self.slot.name
        else:
            s += ', no guid/slot'
        s += ', cipher = ' + self.cipher
        s += ', kdf = ' + self.kdf
        if self.is_sealed:
            s += ', sealed'
        else:
            s += ', UNSEALED'
        s += ', pubkey = ' + repr(self.pubkey)
        s += ')>'
        return s
    def clone(self) -> Box:
        ptr = libpivy.piv_box_clone(self._ptr)
        return Box(ptr = ptr)
    @property
    def has_guidslot(self) -> bool:
        v = libpivy.piv_box_has_guidslot(self._ptr)
        return (v == 1)
    @property
    def guid(self) -> str:
        return libpivy.piv_box_guid_hex(self._ptr).decode('ascii')
    @guid.setter
    def guid(self, hex_guid: str):
        raw = bytes.from_hex(hex_guid)
        libpivy.piv_box_set_guid(self._ptr, raw, len(raw))
    @property
    def slot(self) -> SlotId:
        n = libpivy.piv_box_slot(self._ptr)
        return SlotId(value = n)
    @slot.setter
    def slot(self, slotid: SlotId):
        libpivy.piv_box_set_slot(self._ptr, slotid.value)
    @property
    def pubkey(self) -> Optional[PublicKey]:
        ptr = libpivy.piv_box_pubkey(self._ptr)
        if ptr:
            return PublicKey(owner = self, ptr = ptr)
        else:
            return None
    @property
    def ephem_pubkey(self) -> Optional[PublicKey]:
        ptr = libpivy.piv_box_ephem_pubkey(self._ptr)
        if ptr:
            return PublicKey(owner = self, ptr = ptr)
        else:
            return None
    @property
    def cipher(self) -> str:
        return libpivy.piv_box_cipher(self._ptr).decode('ascii')
    @property
    def kdf(self) -> str:
        return libpivy.piv_box_kdf(self._ptr).decode('ascii')
    @property
    def encsize(self) -> int:
        return libpivy.piv_box_encsize(self._ptr)
    @property
    def is_sealed(self) -> bool:
        v = libpivy.piv_box_sealed(self._ptr)
        return (v == 1)
    @property
    def nonce_size(self) -> int:
        return libpivy.piv_box_nonce_size(self._ptr)
    @property
    def version(self) -> int:
        return libpivy.piv_box_version(self._ptr)

    def set_data(self, data: bytes):
        err = libpivy.piv_box_set_data(self._ptr, data, len(data))
        if err:
            raise Errf(err)
    def set_datab(self, data: SSHBuffer):
        if not isinstance(data, SSHBuffer):
            raise TypeError('"data" must be an SSHBuffer')
        err = libpivy.piv_box_set_datab(self._ptr, data._ptr)
        if err:
            raise Errf(err)

    def seal(self, token: Token, slot: TokenSlot):
        if not isinstance(token, pypivy.Token):
            raise TypeError('"token" must be a Token')
        if not isinstance(slot, pypivy.Slot):
            raise TypeError('"slot" must be a TokenSlot')
        err = libpivy.piv_box_seal(token._ptr, slot._ptr, self._ptr)
        if err:
            raise Errf(err)

    def seal_offline(self, pubkey: PublicKey):
        if not isinstance(pubkey, PublicKey):
            raise TypeError('"pubkey" must be a PublicKey')
        err = libpivy.piv_box_seal_offline(pubkey._ptr, self._ptr)
        if err:
            raise Errf(err)

    def take_data(self) -> bytes:
        dptr = c_void_p()
        dlen = c_size_t()
        err = libpivy.piv_box_take_data(self._ptr, byref(dptr), byref(dlen))
        if err:
            raise Errf(err)
        return string_at(dptr.value, dlen.value)

    def take_datab(self) -> SSHBuffer:
        bptr = c_void_p()
        err = libpivy.piv_box_take_datab(self._ptr, byref(bptr))
        if err:
            raise Errf(err)
        return SSHBuffer(ptr = bptr)

    def find_token(self, tokens: Iterator[Token]) -> Tuple[Token, TokenSlot]:
        if not isinstance(tokens, TokenSet):
            raise TypeError('"tokens" must be a set of tokens from Context')
        tkptr = c_void_p()
        slptr = c_void_p()
        err = libpivy.piv_box_find_token(tokens._ptr, self._ptr, byref(tkptr), byref(slptr))
        if err:
            raise Errf(err)
        token = pypivy.Token(set = tokens, ptr = tkptr)
        slot = pypivy.TokenSlot(token = token, ptr = slptr)
        return (token, slot)
