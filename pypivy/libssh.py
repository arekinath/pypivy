from __future__ import annotations
from pypivy.pivy_ctypes import *

from pypivy.enums import *
import pypivy

class PublicKey:
    """
    Represents a cryptographic public key in SSH format.
    """
    def __init__(self, ptr: Optional[c_void_p] = None, ktype: Optional[KeyType] = None, owner: Optional[object] = None):
        if not ptr and not ktype:
            raise TypeError('PublicKey constructor requires either "ptr" or "ktype"')
        if not ptr:
            ptr = libpivy.sshkey_new(ktype.value)
        if not isinstance(ptr, c_void_p) and not isinstance(ptr, int):
            raise TypeError('"ptr" must be a c_void_p')
        self._owner = owner
        self._ptr = ptr
    def __del__(self):
        if not self._owner:
            libpivy.sshkey_free(self._ptr)
        self._ptr = None
    def __repr__(self):
        fp = self.fingerprint(DigestType.SHA256)
        return f"<PublicKey(type = {self.type}, size = {self.size}, fingerprint = {fp})"
    def __eq__(self, other) -> bool:
        return self.equals(other)
    def equals(self, other) -> bool:
        """
        Tests whether this key is the same public key as another PublicKey
        object.
        """
        if not isinstance(other, PublicKey):
            return False
        if self._ptr == other._ptr:
            return True
        rc = libpivy.sshkey_equal_public(self._ptr, other._ptr)
        return (rc == 1)
    def clone(self) -> PublicKey:
        ptr = c_void_p()
        rc = libpivy.sshkey_from_private(self._ptr, byref(ptr))
        if rc != 0:
            raise LibSSHError('sshkey_demote', rc)
        return PublicKey(ptr = ptr)
    @property
    def type(self) -> KeyType:
        """
        The type of this key, which determines what algorithms it may be used with.
        """
        s = libpivy.sshkey_type(self._ptr).decode('ascii')
        return KeyType[s]
    @property
    def size(self) -> int:
        """
        The size of this public key, in bits.
        """
        return libpivy.sshkey_size(self._ptr)
    def fingerprint(self, digest: DigestType = DigestType.MD5, fptype: FingerprintType = FingerprintType.DEFAULT) -> Optional[str]:
        """
        Calculates an SSH fingerprint for this public key and returns it.
        """
        sptr = libpivy.sshkey_fingerprint(self._ptr, digest.value, fptype.value)
        if sptr:
            fp = sptr.decode('ascii')
            return fp
        else:
            return None
    def verify(self, signature: Signature, data: bytes):
        rc = libpivy.sshkey_verify(self._ptr, \
            signature._sig, len(signature._sig), \
            data, len(data), \
            None, 0, None)
        if rc != 0:
            ex = LibSSHError('sshkey_verify', rc)
            if isinstance(ex, SignatureInvalidError):
                return False
            raise ex
        return True

    def to_ssh(self) -> str:
        b = SSHBuffer()
        rc = libpivy.sshkey_format_text(self._ptr, b._ptr)
        if rc != 0:
            raise LibSSHError('sshkey_format_text', rc)
        return b.to_bytes().decode('ascii')

    @classmethod
    def from_ssh(cls, ssh_string: str, require_all_used: bool = True) -> PublicKey:
        k = PublicKey(ktype = KeyType.UNSPEC)
        buf = create_string_buffer(ssh_string.encode('ascii'))
        ptr = c_void_p(addressof(buf))
        rc = libpivy.sshkey_read(k._ptr, byref(ptr))
        if rc != 0:
            raise LibSSHError('sshkey_read', rc)
        used = ptr.value - addressof(buf)
        if require_all_used and used < len(ssh_string):
            raise LibSSHError('sshkey_read', LibSSHErrorCode.STRING_TOO_LARGE.value)
        return k

class LibSSHError(Exception):
    def __init__(self, func: str, rc: int = LibSSHErrorCode.INTERNAL_ERROR.value):
        self._func = func
        self._rc = rc
        self._name = LibSSHErrorCode(value = rc)
        self._desc = libpivy.ssh_err(rc).decode('utf-8')
        super().__init__(func + ' returned ' + repr(self._name) + ' (' + self._desc + ')')
    def __new__(cls, func: str, rc: int) -> Errf:
        """
        Uses the `name` of the given errf_t pointer to locate a subclass of
        Errf with the same name. Returns an instance of that class. If no
        matching subclass exists, returns an instance of Errf itself.
        """
        if rc == LibSSHErrorCode.ALLOC_FAIL:
            return MemoryError(func + ' returned ALLOC_FAIL (out of memory)')
        for scls in cls.__subclasses__():
            if scls._err_rc == rc:
                return Exception.__new__(scls, func, rc)
        return Exception.__new__(LibSSHError, func, rc)
    @property
    def name(self) -> LibSSHErrorCode:
        return self._name
    @property
    def function(self) -> str:
        return self._func
    @property
    def return_code(self) -> int:
        return self._rc
    @property
    def description(self) -> str:
        return self._desc

class MessageIncompleteError(LibSSHError):
    _err_rc = LibSSHErrorCode.MESSAGE_INCOMPLETE.value

class MACInvalidError(LibSSHError):
    _err_rc = LibSSHErrorCode.MAC_INVALID.value

class SignatureInvalidError(LibSSHError):
    _err_rc = LibSSHErrorCode.SIGNATURE_INVALID.value

class StringTooLargeError(LibSSHError):
    _err_rc = LibSSHErrorCode.STRING_TOO_LARGE.value

class Signature:
    def __init__(self, key: PublicKey, digest: DigestType, signature: bytes):
        self._key = key
        self._digest = digest
        self._sig = signature

    def __repr__(self):
        return f"<Signature(key_type = {self.key_type}, digest = {self.digest_type})>"

    @property
    def key(self) -> PublicKey:
        return self._key
    @property
    def key_type(self) -> KeyType:
        return self._key.type
    @property
    def digest_type(self) -> DigestType:
        return self._digest

    def to_ssh(self) -> bytes:
        return self._sig
    def to_asn1(self) -> bytes:
        buf = SSHBuffer.from_bytes(self._sig)
        outbuf = SSHBuffer()
        dtype = c_int()
        rc = libpivy.sshkey_to_asn1(self._ptr, buf._ptr, byref(dtype), outbuf._ptr)
        if rc != 0:
            raise LibSSHError('sshkey_to_asn1', rc)
        return outbuf.to_bytes()

    @classmethod
    def from_ssh(cls, key: PublicKey, data: bytes) -> Signature:
        ptr = c_char_p()
        rc = libpivy.sshkey_get_sigtype(data, len(data), byref(ptr))
        if rc != 0:
            raise LibSSHError('sshkey_get_sigtype', rc)
        sigtype = ptr.decode('ascii')
        if sigtype == 'ecdsa-sha2-nistp256':
            digest = DigestType.SHA256
        elif sigtype == 'ecdsa-sha2-nistp384':
            digest = DigestType.SHA384
        elif sigtype == 'ecdsa-sha2-nistp521':
            digest = DigestType.SHA512
        elif sigtype == 'rsa-sha2-256':
            digest = DigestType.SHA256
        elif sigtype == 'rsa-sha2-512':
            digest = DigestType.SHA512
        elif sigtype == 'ssh-rsa':
            digest = DigestType.SHA1
        elif sigtype == 'ssh-ed25519':
            digest = DigestType.SHA512
        else:
            raise Exception('Algorithm not supported: ' + sigtype)
        return Signature(key = key, digest = digest, signature = data)

    @classmethod
    def from_asn1(cls, key: PublicKey, digest: DigestType, data: bytes) -> Signature:
        buf = SSHBuffer()
        rc = libpivy.sshkey_sig_from_asn1(key._ptr, digest.value, data, len(data), buf._ptr)
        if rc != 0:
            raise LibSSHError('sshkey_sig_from_asn1', rc)
        return Signature(key = key, digest = digest, signature = buf.to_bytes())

class SSHBuffer:
    def __init__(self, ptr: Optional[c_void_p] = None):
        if not ptr:
            ptr = libpivy.sshbuf_new()
            if not ptr:
                raise MemoryError
        self._ptr = ptr
    def __del__(self):
        libpivy.sshbuf_free(self._ptr)
        self._ptr = None

    def __repr__(self):
        return f"<SSHBuffer(len = {self.len})>"

    @property
    def len(self) -> int:
        return libpivy.sshbuf_len(self._ptr)
    @property
    def avail(self) -> int:
        return libpivy.sshbuf_avail(self._ptr)

    def reset(self):
        libpivy.sshbuf_reset(self._ptr)
    def put(self, data: bytes):
        rc = libpivy.sshbuf_put(self._ptr, data, len(data))
        if rc != 0:
            raise LibSSHError('sshbuf_put', rc)
    def putb(self, other: SSHBuffer):
        if not isinstance(other, SSHBuffer):
            raise TypeError('Argument "other" must be an SSHBuffer')
        rc = libpivy.sshbuf_putb(self._ptr, other._ptr)
        if rc != 0:
            raise LibSSHError('sshbuf_putb', rc)
    def put_b64(self, b64: str):
        rc = libpivy.sshbuf_b64tod(self._ptr, b64.encode('utf-8'))
        if rc != 0:
            raise LibSSHError('sshbuf_b64tod', rc)
    def get(self, nbytes: int) -> bytes:
        buf = create_string_buffer(nbytes)
        rc = libpivy.sshbuf_get(self._ptr, buf, nbytes)
        if rc != 0:
            raise LibSSHError('sshbuf_get', rc)
        return buf.raw
    def get_u64(self) -> int:
        v = c_ulonglong()
        rc = libpivy.sshbuf_get_u64(self._ptr, byref(v))
        if rc != 0:
            raise LibSSHError(rc)
        return v.value
    def get_u32(self) -> int:
        v = c_uint()
        rc = libpivy.sshbuf_get_u32(self._ptr, byref(v))
        if rc != 0:
            raise LibSSHError(rc)
        return v.value
    def get_u16(self) -> int:
        v = c_ushort()
        rc = libpivy.sshbuf_get_u16(self._ptr, byref(v))
        if rc != 0:
            raise LibSSHError(rc)
        return v.value
    def get_u8(self) -> int:
        v = c_ubyte()
        rc = libpivy.sshbuf_get_u8(self._ptr, byref(v))
        if rc != 0:
            raise LibSSHError(rc)
        return v.value
    def put_u64(self, v: int):
        rc = libpivy.sshbuf_put_u64(self._ptr, v)
        if rc != 0:
            raise LibSSHError(rc)
    def to_bytes(self) -> bytes:
        ptr = libpivy.sshbuf_ptr(self._ptr)
        nbytes = libpivy.sshbuf_len(self._ptr)
        return string_at(ptr, nbytes)
    def to_hex(self) -> str:
        ptr = libpivy.sshbuf_dtob16(self._ptr)
        if ptr:
            s = ptr.decode('ascii')
            pythonapi.free(ptr)
            return s
        else:
            raise LibSSHError('sshbuf_dtob16')
    def to_base64(self, wrap: bool = False) -> str:
        iwrap = 1
        if not wrap:
            iwrap = 0
        ptr = libpivy.sshbuf_dtob64_string(self._ptr, iwrap)
        if ptr:
            s = ptr.decode('ascii')
            pythonapi.free(ptr)
            return s
        else:
            raise LibSSHError('sshbuf_dtob64_string')

    @classmethod
    def from_bytes(cls, data: bytes) -> SSHBuffer:
        buf = SSHBuffer()
        buf.put(data)
        return buf

    @classmethod
    def from_b64(cls, b64: str) -> SSHBuffer:
        buf = SSHBuffer()
        buf.put_b64(b64)
        return buf
