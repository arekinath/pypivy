from __future__ import annotations
from pypivy.pivy_ctypes import *

import pypivy
from pypivy.enums import *
from pypivy.errf import Errf
from pypivy.libssh import PublicKey
from pypivy.ebox import Ebox, EboxTpl

class Cert:
	def __init__(self, ptr: Optional[c_void_p] = None, owner: Optional[object] = None):
		if ptr is None:
			ptr = libpivy.X509_new()
			owner = None
		self._ptr = ptr
		self._owner = owner

	def __del__(self):
		if self._owner is None:
			libpivy.X509_free(self._ptr)
		self._ptr = None

	def to_der(self) -> bytes:
		dptr = c_void_p()
		dlen = c_size_t()
		err = libpivy.X509_to_der(self._ptr, byref(dptr), byref(dlen))
		if err:
			raise Errf(err)
		return string_at(dptr.value, dlen.value)

class CertReq:
	def __init__(self, ptr: Optional[c_void_p] = None):
		if ptr is None:
			ptr = libpivy.X509_REQ_new()
		self._ptr = ptr

	def __del__(self):
		libpivy.X509_REQ_free(self._ptr)
		self._ptr = None

	def to_der(self) -> bytes:
		dptr = c_void_p()
		dlen = c_size_t()
		err = libpivy.X509_REQ_to_der(self._ptr, byref(dptr), byref(dlen))
		if err:
			raise Errf(err)
		return string_at(dptr.value, dlen.value)

class CRL:
	def __init__(self, ptr: Optional[c_void_p] = None):
		if ptr is None:
			ptr = libpivy.X509_CRL_new()
		self._ptr = ptr

	def __del__(self):
		libpivy.X509_CRL_free(self._ptr)
		self._ptr = None

	def to_der(self) -> bytes:
		dptr = c_void_p()
		dlen = c_size_t()
		err = libpivy.X509_CRL_to_der(self._ptr, byref(dptr), byref(dlen))
		if err:
			raise Errf(err)
		return string_at(dptr.value, dlen.value)

class CA:
	def __init__(self, ptr: c_void_p):
		self._ptr = ptr

	def __del__(self):
		libpivy.ca_close(self._ptr)
		self._ptr = None

	@property
	def slug(self) -> str:
		return libpivy.ca_slug(self._ptr).decode('utf-8')

	@property
	def guid_hex(self) -> str:
		return libpivy.ca_guidhex(self._ptr).decode('ascii')

	@property
	def public_key(self) -> PublicKey:
		ptr = libpivy.ca_pubkey(self._ptr)
		return PublicKey(owner = self, ptr = ptr)

	@property
	def card_auth_key(self) -> PublicKey:
		ptr = libpivy.ca_cak(self._ptr)
		return PublicKey(owner = self, ptr = ptr)

	@property
	def dn(self) -> str:
		return libpivy.ca_dn(self._ptr).decode('utf-8')

	@property
	def crl_uris(self) -> List[str]:
		count = libpivy.ca_crl_uri_count(self._ptr)
		uris = []
		for i in range(0, count):
			uri = libpivy.ca_crl_uri(self._ptr, i).decode('utf-8')
			uris.append(uri)
		return uris
	@property
	def ocsp_uris(self) -> List[str]:
		count = libpivy.ca_ocsp_uri_count(self._ptr)
		uris = []
		for i in range(0, count):
			uri = libpivy.ca_ocsp_uri(self._ptr, i).decode('utf-8')
			uris.append(uri)
		return uris
	@property
	def aia_uris(self) -> List[str]:
		count = libpivy.ca_aia_uri_count(self._ptr)
		uris = []
		for i in range(0, count):
			uri = libpivy.ca_aia_uri(self._ptr, i).decode('utf-8')
			uris.append(uri)
		return uris

	@property
	def pin_ebox(self) -> Optional[Ebox]:
		ptr = libpivy.ca_get_ebox(self._ptr, CAEboxType.PIN)
		if ptr:
			return Ebox(owner = self, ptr = ptr)
		else:
			return None
	@property
	def old_pin_ebox(self) -> Optional[Ebox]:
		ptr = libpivy.ca_get_ebox(self._ptr, CAEboxType.OLD_PIN)
		if ptr:
			return Ebox(owner = self, ptr = ptr)
		else:
			return None
	@property
	def puk_ebox(self) -> Optional[Ebox]:
		ptr = libpivy.ca_get_ebox(self._ptr, CAEboxType.PUK)
		if ptr:
			return Ebox(owner = self, ptr = ptr)
		else:
			return None
	@property
	def key_backup_ebox(self) -> Optional[Ebox]:
		ptr = libpivy.ca_get_ebox(self._ptr, CAEboxType.KEY_BACKUP)
		if ptr:
			return Ebox(owner = self, ptr = ptr)
		else:
			return None

	@property
	def pin_ebox_tpl(self) -> Optional[str]:
		s = libpivy.ca_get_ebox_tpl(self._ptr, CAEboxType.PIN)
		if s:
			return s.decode('utf-8')
		else:
			return None
	@property
	def old_pin_ebox_tpl(self) -> Optional[str]:
		s = libpivy.ca_get_ebox_tpl(self._ptr, CAEboxType.OLD_PIN)
		if s:
			return s.decode('utf-8')
		else:
			return None
	@property
	def puk_ebox_tpl(self) -> Optional[str]:
		s = libpivy.ca_get_ebox_tpl(self._ptr, CAEboxType.PUK)
		if s:
			return s.decode('utf-8')
		else:
			return None
	@property
	def key_backup_ebox_tpl(self) -> Optional[str]:
		s = libpivy.ca_get_ebox_tpl(self._ptr, CAEboxType.KEY_BACKUP)
		if s:
			return s.decode('utf-8')
		else:
			return None

	def ebox_tpl_by_name(self, name: str) -> Optional[EboxTpl]:
		ptr = libpivy.ca_get_ebox_tpl_name(self._ptr, name.encode('utf-8'))
		if ptr:
			return EboxTpl(owner = self, ptr = ptr)
		else:
			return None

	@classmethod
	def open(self, path: str) -> CA:
		ptr = c_void_p()
		err = libpivy.ca_open(path.encode('utf-8'), byref(ptr))
		if err:
			raise Errf(err)
		return CA(ptr = ptr)

class CASession:
	def __init__(self, ca: CA):
		self._ca = ca
		if not isinstance(ca, CA):
			raise TypeError('ca argument must be a CA instance')
		ptr = c_void_p()
		err = libpivy.ca_open_session(ca._ptr, byref(ptr))
		if err:
			raise Errf(err)
		self._ptr = ptr

	def __del__(self):
		self.close()

	def close(self):
		if self._ptr:
			libpivy.ca_close_session(self._ptr)
		self._ptr = None

	@property
	def authed(self) -> bool:
		v = libpivy.ca_session_authed(self._ptr)
		return (v == 1)

	@property
	def auth_type(self) -> AuthMethod:
		v = libpivy.ca_session_auth_type(self._ptr)
		return AuthMethod(value = v)

	def auth(self, method: AuthMethod, pin: str):
		err = libpivy.ca_session_auth(self._ptr, method.value, pin.encode('ascii'))
		if err:
			raise Errf(err)

	def rotate_pin(self):
		err = libpivy.ca_rotate_pin(self._ptr)
		if err:
			raise Errf(err)

	def generate_crl(self):
		crl = CRL()
		err = libpivy.ca_generate_crl(self._ca._ptr, self._ptr, crl._ptr)
		if err:
			raise Errf(err)
		return crl

class CertVarScope:
	def __init__(self, ptr: Optional[c_void_p] = None, parent: Optional[CertVarScope] = None):
		if ptr is None:
			ptr = libpivy.scope_new_root()
			parent = None
		self._parent = parent
		self._ptr = ptr

	def __del__(self):
		if self._parent is None:
			libpivy.scope_free_root(self._ptr)
		self._ptr = None

class CertVarChain:
	def __init__(self, ptr: c_void_p):
		self._ptr = ptr

	def __del__(self):
		libpivy.cert_var_free_all(self._ptr)
		self._ptr = None

	def __iter__(self):
		return CertVarIterator(chain = self, root = self._ptr)

class CertVarIterator:
	def __init__(self, chain: CertVarChain, root: c_void_p):
		self._chain = chain
		self._ptr = root

	def __next__(self):
		ptr = self._ptr
		if ptr:
			self._ptr = libpivy.cert_var_next(ptr)
			return CertVar(owner = self._chain, ptr = ptr)
		else:
			raise StopIteration

class CertVar:
	def __init__(self, ptr: c_void_p, owner: Optional[object] = None):
		self._owner = owner
		self._ptr = ptr

class CertTpl:
	def __init__(self, ptr: c_void_p):
		self._ptr = ptr

	@property
	def name(self) -> str:
		return libpivy.cert_tpl_name(self._ptr).decode('ascii')

	@property
	def help(self) -> str:
		return libpivy.cert_tpl_help(self._ptr).decode('ascii')

	def __repr__(self) -> str:
		return f"<CertTpl(name = {self.name}, help = {self.help})>"

	@classmethod
	def all(cls) -> Iterator[CertTpl]:
		return CertTplGlobalSet()

	@classmethod
	def find(cls, name: str) -> Optional[CertTpl]:
		ptr = libpivy.cert_tpl_find(name.encode('ascii'))
		if ptr:
			return CertTpl(ptr = ptr)
		else:
			return None

class CertTplGlobalSet:
	def __init__(self):
		self._ptr = libpivy.cert_tpl_first()
	def __iter__(self):
		return CertTplIterator(self._ptr)

class CertTplIterator:
	def __init__(self, ptr: c_void_p):
		self._ptr = ptr
	def __next__(self):
		ptr = self._ptr
		if ptr:
			self._ptr = libpivy.cert_tpl_next(ptr)
			return CertTpl(ptr = ptr)
		else:
			raise StopIteration

