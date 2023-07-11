from __future__ import annotations
from pypivy.pivy_ctypes import *

import pypivy
from pypivy.enums import *
from pypivy.errf import Errf
from pypivy.libssh import PublicKey, SSHBuffer
from pypivy.context import TokenSet

class EboxTpl:
    def __init__(self, ptr: Optional[c_void_p] = None, owner: Optional[object] = None):
        self._owner = owner
        if ptr is None:
            ptr = libpivy.ebox_tpl_alloc()
        self._ptr = ptr

    def __del__(self):
        if self._ptr is not None and self._owner is None:
            libpivy.ebox_tpl_free(self._ptr)
        self._ptr = None

    def __iter__(self):
        return EboxTplConfigIterator(tpl = self)

    def __repr__(self):
        configs = []
        for config in self:
            configs.append(config.__repr__())
        return f"<EboxTpl(version = {self.version}, configs = {configs})>"

    @property
    def version(self) -> int:
        return libpivy.ebox_tpl_version(self._ptr)

    def clone(self) -> EboxTpl:
        ptr = libpivy.ebox_tpl_clone(self._ptr)
        return EboxTpl(ptr = ptr)

    def add(self, config: EboxTplConfig):
        if not isinstance(config, pivy.EboxTplConfig):
            raise TypeError('config must be an EboxTplConfig instance')
        if config._owner is not None:
            raise ValueError('config must not be owned by another object')
        libpivy.ebox_tpl_add_config(self._ptr, config._ptr)
        config._owner = self

    def remove(self, config: EboxTplConfig):
        if not isinstance(config, pivy.EboxTplConfig):
            raise TypeError('config must be an EboxTplConfig instance')
        if config._owner != self:
            raise ValueError('config must not be owned by another object')
        libpivy.ebox_tpl_remove_config(self._ptr, config._ptr)
        config._owner = None

    def encode(self) -> bytes:
        b = SSHBuffer()
        err = libpivy.sshbuf_put_ebox_tpl(b._ptr, self._ptr)
        if err:
            raise Errf(err)
        return b.to_bytes()

    @classmethod
    def decode(cls, data: bytes) -> EboxTpl:
        b = SSHBuffer()
        b.put(data)
        return EboxTpl.decode_sshbuf(b)

    @classmethod
    def decode_sshbuf(cls, buf: SSHBuffer) -> EboxTpl:
        if not isinstance(buf, SSHBuffer):
            raise TypeError('buffer must be an SSHBuffer instance')
        ptr = c_void_p()
        err = libpivy.sshbuf_get_ebox_tpl(buf._ptr, byref(ptr))
        if err:
            raise Errf(err)
        return EboxTpl(ptr = ptr)

class EboxTplConfigIterator:
    def __init__(self, tpl: EboxTpl):
        self._tpl = tpl
        self._ptr = libpivy.ebox_tpl_next_config(self._tpl._ptr, None)

    def __next__(self):
        ptr = self._ptr
        if ptr:
            self._ptr = libpivy.ebox_tpl_next_config(self._tpl._ptr, ptr)
            return EboxTplConfig(owner = self._tpl, ptr = ptr)
        else:
            raise StopIteration

class EboxTplConfig:
    def __init__(self, ptr: Optional[c_void_p] = None, ctype: Optional[EboxConfigType] = None, owner: Optional[object] = None):
        self._owner = owner
        if ptr is None and ctype is None:
            raise ValueError('Need either ptr or ctype')
        if ptr is None:
            ptr = libpivy.ebox_tpl_config_alloc(ctype.value)
        self._ptr = ptr

    def __del__(self):
        if self._ptr is not None and self._owner is None:
            libpivy.ebox_tpl_config_free(self._ptr)
        self._ptr = None

    def __repr__(self):
        parts = []
        for part in self:
            parts.append(part.__repr__())
        return f"<EboxTplConfig(type = {self.type}, n = {self.n_value}, parts = {parts})>"

    def __iter__(self):
        return EboxTplPartIterator(config = self)

    @property
    def type(self) -> EboxConfigType:
        v = libpivy.ebox_tpl_config_type(self._ptr)
        return EboxConfigType(value = v)

    @property
    def n_value(self) -> int:
        return libpivy.ebox_tpl_config_n(self._ptr)

    def add(self, part: EboxTplPart):
        if not isinstance(part, pivy.EboxTplPart):
            raise TypeError('part must be an EboxTplPart instance')
        if part._owner is not None:
            raise ValueError('part must not be owned by another object')
        libpivy.ebox_tpl_config_add_part(self._ptr, part._ptr)
        part._owner = self

    def remove(self, part: EboxTplPart):
        if not isinstance(part, pivy.EboxTplPart):
            raise TypeError('part must be an EboxTplPart instance')
        if part._owner != self:
            raise ValueError('part must not be owned by another object')
        libpivy.ebox_tpl_config_remove_part(self._ptr, part._ptr)
        part._owner = None

class EboxTplPartIterator:
    def __init__(self, config: EboxTplConfig):
        self._config = config
        self._ptr = libpivy.ebox_tpl_config_next_part(self._config._ptr, None)

    def __next__(self):
        ptr = self._ptr
        if ptr:
            self._ptr = libpivy.ebox_tpl_config_next_part(self._config._ptr, ptr)
            return EboxTplPart(owner = self._config, ptr = ptr)
        else:
            raise StopIteration

class EboxTplPart:
    def __init__(self, ptr: Optional[c_void_p] = None, guid: Optional[bytes] = None,
                 slot: Optional[SlotId] = None, public_key: Optional[PublicKey] = None,
                 owner: Optional[object] = None):
        self._owner = owner
        if ptr is None and (guid is None or slot is None or public_key is None):
            raise ValueError('Need either ptr or guid/slot/public_key')
        if ptr is None:
            if not isinstance(public_key, PublicKey):
                raise TypeError('public_key must be a PublicKey instance')
            ptr = libpivy.ebox_tpl_part_alloc(guid, len(guid), slot.value, public_key._ptr)
        self._ptr = ptr

    def __del__(self):
        if self._ptr is not None and self._owner is None:
            libpivy.ebox_tpl_part_free(self._ptr)
        self._ptr = None

    def __repr__(self):
        return f"<EboxTplPart(name = {self.name}, guid = {self.guid_hex}, slot = {self.slot}, pubkey = {self.public_key})>"

    @property
    def name(self) -> Optional[str]:
        s = libpivy.ebox_tpl_part_name(self._ptr)
        if s:
            return s.decode('utf-8')
        else:
            return None
    @name.setter
    def name(self, v: Optional[str]):
        vptr = None
        if v is not None:
            vptr = v.encode('utf-8')
        libpivy.ebox_tpl_part_set_name(self._ptr, vptr)

    @property
    def card_auth_key(self) -> Optional[PublicKey]:
        ptr = libpivy.ebox_tpl_part_cak(self._ptr)
        if ptr:
            return PublicKey(owner = self, ptr = ptr)
        else:
            return None
    @card_auth_key.setter
    def card_auth_key(self, v: Optional[PublicKey]):
        vptr = None
        if v is not None:
            if not isinstance(v, PublicKey):
                raise TypeError('card_auth_key value must be a PublicKey instance')
            vptr = v._ptr
        libpivy.ebox_tpl_part_set_cak(self._ptr, vptr)

    @property
    def public_key(self) -> PublicKey:
        ptr = libpivy.ebox_tpl_part_pubkey(self._ptr)
        return PublicKey(owner = self, ptr = ptr)

    @property
    def slot(self) -> SlotId:
        v = libpivy.ebox_tpl_part_slot(self._ptr)
        return SlotId(value = v)

    @property
    def guid_hex(self) -> str:
        dptr = libpivy.ebox_tpl_part_guid(self._ptr)
        byts = string_at(dptr, 16)
        return byts.hex()

class Ebox:
    def __init__(self, ptr: c_void_p, owner: Optional[object] = None):
        self._owner = owner
        self._ptr = ptr

    def __del__(self):
        if self._ptr is not None and self._owner is None:
            libpivy.ebox_free(self._ptr)
        self._ptr = None

    @property
    def version(self) -> int:
        return libpivy.ebox_version(self._ptr)

    @property
    def type(self) -> EboxType:
        v = libpivy.ebox_type(self._ptr)
        return EboxType(value = v)

    @property
    def is_unlocked(self) -> bool:
        v = libpivy.ebox_is_unlocked(self._ptr)
        return (v == 1)

    @property
    def template(self) -> EboxTpl:
        return EboxTpl(owner = self, ptr = libpivy.ebox_tpl(self._ptr))


class EboxConfig:
    def __init__(self, ebox: Ebox, ptr: c_void_p):
        self._ebox = ebox
        self._ptr = ptr

    @property
    def template(self) -> EboxTplConfig:
        return EboxTplConfig(owner = self,
            ptr = libpivy.ebox_config_tpl(self._ptr))

class EboxPart:
    def __init__(self, ebox: Ebox, ptr: c_void_p):
        self._ebox = ebox
        self._ptr = ptr

    @property
    def template(self) -> EboxTplPart:
        return EboxTplPart(owner = self,
            ptr = libpivy.ebox_part_tpl(self._ptr))

class EboxChallenge:
    def __init__(self, ptr: c_void_p, owner: Optional[object] = None):
        self._owner = owner
        self._ptr = ptr

    def __del__(self):
        if self._ptr is not None and self._owner is None:
            libpivy.ebox_challenge_free(self._ptr)
        self._ptr = None

class EboxStream:
    def __init__(self, ptr: Optional[c_void_p] = None, template: Optional[EboxTpl] = None):
        if ptr is None and template is None:
            raise ValueError('One of ptr or template is required')
        if ptr is None:
            if not isinstance(template, EboxTpl):
                raise TypeError('template must be an EboxTpl')
            ptr = c_void_p()
            err = libpivy.ebox_stream_new(template._ptr, byref(ptr))
            if err:
                raise Errf(err)
        self._ptr = ptr

    def __del__(self):
        libpivy.ebox_stream_free(self._ptr)
        self._ptr = None

class EboxStreamChunk:
    def __init__(self, stream: EboxStream, ptr: c_void_p):
        self._stream = stream
        self._ptr = ptr

    def __del__(self):
        libpivy.ebox_stream_chunk_free(self._ptr)
        self._ptr = None
