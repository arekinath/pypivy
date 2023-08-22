from __future__ import annotations
from pypivy.pivy_ctypes import *

from pypivy.enums import *
from pypivy.errf import Errf
from pypivy.context import TokenSet

class Cardcap:
    def __init__(self, ptr: Optional[c_void_p] = None):
        if ptr is None:
            ptr = libpivy.piv_cardcap_new()
        self._ptr = ptr
    def __del__(self):
        libpivy.piv_cardcap_free(self._ptr)
    def __repr__(self):
        return f"<Cardcap({self.data_model}, type = {self.card_type}, id = {self.id_hex})>"

    @property
    def card_type(self) -> CardcapType:
        v = libpivy.piv_cardcap_type(self._ptr)
        return CardcapType(value = v)
    @card_type.setter
    def card_type(self, v: CardcapType):
        if not isinstance(v, CardcapType):
            raise TypeError('card_type must be set to a CardcapType')
        libpivy.piv_cardcap_set_type(self._ptr, v.value)

    @property
    def data_model(self) -> CardcapDataModel:
        v = libpivy.piv_cardcap_data_model(self._ptr)
        return CardcapDataModel(value = v)
    @data_model.setter
    def data_model(self, v: CardcapDataModel):
        if not isinstance(v, CardcapDataModel):
            raise TypeError('data_model must be set to a CardcapDataModel')
        libpivy.piv_cardcap_set_data_model(self._ptr, v.value)

    @property
    def id_hex(self) -> Optional[str]:
        s = libpivy.piv_cardcap_id_hex(self._ptr)
        if s:
            return s.decode('ascii')
        else:
            return None

    def set_random_id(self):
        libpivy.piv_cardcap_set_random_id(self._ptr)

    @property
    def manufacturer(self) -> int:
        return libpivy.piv_cardcap_manufacturer(self._ptr)
    @manufacturer.setter
    def manufacturer(self, v: int):
        libpivy.piv_cardcap_set_manufacturer(self._ptr, v)

class PrintedInfo:
    def __init__(self, ptr: Optional[c_void_p] = None):
        if ptr is None:
            ptr = libpivy.piv_pinfo_new()
        self._ptr = ptr
    def __del__(self):
        libpivy.piv_pinfo_free(self._ptr)

    def __repr__(self):
        has_admin = (self.ykpiv_admin_key is not None)
        return f"<PrintedInfo(name = {self.name}, serial = {self.serial}, issuer = {self.issuer}, expiry = {self.expiry}, has_admin = {has_admin})>"

    @property
    def name(self) -> Optional[str]:
        s = libpivy.piv_pinfo_get_name(self._ptr)
        return s.decode('utf-8') if s else None
    @property
    def affiliation(self) -> Optional[str]:
        s = libpivy.piv_pinfo_get_affiliation(self._ptr)
        return s.decode('utf-8') if s else None
    @property
    def expiry(self) -> Optional[str]:
        s = libpivy.piv_pinfo_get_expiry(self._ptr)
        return s.decode('utf-8') if s else None
    @property
    def serial(self) -> Optional[str]:
        s = libpivy.piv_pinfo_get_serial(self._ptr)
        return s.decode('utf-8') if s else None
    @property
    def issuer(self) -> Optional[str]:
        s = libpivy.piv_pinfo_get_issuer(self._ptr)
        return s.decode('utf-8') if s else None
    @property
    def org_line_1(self) -> Optional[str]:
        s = libpivy.piv_pinfo_get_org_line_1(self._ptr)
        return s.decode('utf-8') if s else None
    @property
    def org_line_2(self) -> Optional[str]:
        s = libpivy.piv_pinfo_get_org_line_2(self._ptr)
        return s.decode('utf-8') if s else None
    @name.setter
    def name(self, v: Optional[str]):
        v = v.encode('utf-8') if v is not None else None
        libpivy.piv_pinfo_set_name(self._ptr, v)
    @affiliation.setter
    def affiliation(self, v: Optional[str]):
        v = v.encode('utf-8') if v is not None else None
        libpivy.piv_pinfo_set_affiliation(self._ptr, v)
    @expiry.setter
    def expiry(self, v: Optional[str]):
        v = v.encode('utf-8') if v is not None else None
        libpivy.piv_pinfo_set_expiry(self._ptr, v)
    @serial.setter
    def serial(self, v: Optional[str]):
        v = v.encode('utf-8') if v is not None else None
        libpivy.piv_pinfo_set_serial(self._ptr, v)
    @issuer.setter
    def issuer(self, v: Optional[str]):
        v = v.encode('utf-8') if v is not None else None
        libpivy.piv_pinfo_set_issuer(self._ptr, v)
    @org_line_1.setter
    def org_line_1(self, v: Optional[str]):
        v = v.encode('utf-8') if v is not None else None
        libpivy.piv_pinfo_set_org_line_1(self._ptr, v)
    @org_line_2.setter
    def org_line_2(self, v: Optional[str]):
        v = v.encode('utf-8') if v is not None else None
        libpivy.piv_pinfo_set_org_line_2(self._ptr, v)

    def set_expiry_rel(self, secs: int):
        libpivy.piv_pinfo_set_expiry_rel(self._ptr, secs)

    @property
    def ykpiv_admin_key(self) -> Optional[bytes]:
        sz = c_size_t()
        ptr = libpivy.ykpiv_pinfo_get_admin_key(self._ptr, byref(sz))
        if sz.value > 0 and ptr:
            return string_at(ptr, sz.value)
        else:
            return None
    @ykpiv_admin_key.setter
    def ykpiv_admin_key(self, v: bytes):
        libpivy.ykpiv_pinfo_set_admin_key(self._ptr, v, len(v))

class Chuid:
    def __init__(self, ptr: Optional[c_void_p] = None, owner: Optional[object] = None):
        if ptr is None:
            ptr = libpivy.piv_chuid_new()
        self._owner = owner
        self._ptr = ptr
    def __del__(self):
        if not self._owner:
            libpivy.piv_chuid_free(self._ptr)
    def __repr__(self):
        return '<Chuid(guid = ' + self.guid + ', expiry = ' + repr(self.expiry) + \
            ', fascn = ' + repr(self.fascn) + ')>'
    def clone(self) -> Chuid:
        ptr = c_void_p()
        err = libpivy.piv_chuid_clone(self._ptr, byref(ptr))
        if err:
            raise Errf(err)
        return Chuid(ptr = ptr)
    @property
    def fascn(self) -> Optional[Fascn]:
        ptr = libpivy.piv_chuid_get_fascn(self._ptr)
        if ptr:
            return Fascn(owner = self, ptr = ptr)
        else:
            return None
    @fascn.setter
    def fascn(self, fascn: Fascn):
        if self._owner:
            raise PermissionError('CHUID is read-only')
        libpivy.piv_chuid_set_fascn(self._ptr, fascn._ptr)
    @property
    def guid(self) -> str:
        return libpivy.piv_chuid_get_guidhex(self._ptr).decode('ascii')
    @guid.setter
    def guid(self, guid_hex: str):
        if self._owner:
            raise PermissionError('CHUID is read-only')
        guid = bytes.fromhex(str)
        if len(guid) != 16:
            raise ValueError('GUID must be 16 bytes in length')
        libpivy.piv_chuid_set_guid(self._ptr, guid)
    @property
    def expiry(self) -> bytes:
        sz = c_size_t()
        ptr = libpivy.piv_chuid_get_expiry(self._ptr, byref(sz))
        return string_at(ptr, sz.value)
    def set_expiry_rel(self, seconds: int):
        if self._owner:
            raise PermissionError('CHUID is read-only')
        libpivy.piv_chuid_set_expiry_rel(self._ptr, seconds)
    def set_random_guid(self):
        if self._owner:
            raise PermissionError('CHUID is read-only')
        libpivy.piv_chuid_set_random_guid(self._ptr)

class Fascn:
    def __init__(self, ptr: Optional[c_void_p] = None, owner: Optional[object] = None):
        if ptr is None:
            ptr = libpivy.piv_fascn_zero()
        self._owner = owner
        self._ptr = ptr
    def __del__(self):
        if not self._owner:
            libpivy.piv_fascn_free(self._ptr)

    def clone(self) -> Fascn:
        ptr = libpivy.piv_fascn_clone(self._ptr)
        return Fascn(ptr = ptr)

    def encode(self) -> bytes:
        sz = c_size_t()
        ptr = c_void_p()
        err = libpivy.piv_fascn_encode(self._ptr, byref(ptr), byref(sz))
        if err:
            raise Errf(err)
        return string_at(ptr.value, sz.value)

    @classmethod
    def decode(cls, data: bytes) -> Fascn:
        ptr = c_void_p()
        err = libpivy.piv_fascn_decode(data, len(data), byref(ptr))
        if err:
            raise Errf(err)
        return Fascn(ptr = ptr)

    @property
    def agency_code(self) -> str:
        return libpivy.piv_fascn_get_agency_code(self._ptr).decode('ascii')
    @agency_code.setter
    def agency_code(self, v: str):
        if self._owner:
            raise PermissionError('FASC-N is read-only')
        if len(v) != 4 or not v.isdigit():
            raise ValueError('Agency code must be 4 digits long')
        libpivy.piv_fascn_set_agency_code(self._ptr, v.encode('ascii'))
    @property
    def system_code(self) -> str:
        return libpivy.piv_fascn_get_system_code(self._ptr).decode('ascii')
    @system_code.setter
    def system_code(self, v: str):
        if self._owner:
            raise PermissionError('FASC-N is read-only')
        if len(v) != 4 or not v.isdigit():
            raise ValueError('System code must be 4 digits long')
        libpivy.piv_fascn_set_system_code(self._ptr, v.encode('ascii'))
    @property
    def cred_number(self) -> str:
        return libpivy.piv_fascn_get_cred_number(self._ptr).decode('ascii')
    @cred_number.setter
    def cred_number(self, v: str):
        if self._owner:
            raise PermissionError('FASC-N is read-only')
        if len(v) != 6 or not v.isdigit():
            raise ValueError('Cred number must be 6 digits long')
        libpivy.piv_fascn_set_cred_number(self._ptr, v.encode('ascii'))
    @property
    def cred_series(self) -> str:
        return libpivy.piv_fascn_get_cred_series(self._ptr).decode('ascii')
    @cred_series.setter
    def cred_series(self, v: str):
        if self._owner:
            raise PermissionError('FASC-N is read-only')
        if len(v) != 1 or not v.isdigit():
            raise ValueError('Cred series must be 1 digit long')
        libpivy.piv_fascn_set_cred_series(self._ptr, v.encode('ascii'))
    @property
    def indiv_cred_issue(self) -> str:
        return libpivy.piv_fascn_get_indiv_cred_issue(self._ptr).decode('ascii')
    @indiv_cred_issue.setter
    def indiv_cred_issue(self, v: str):
        if self._owner:
            raise PermissionError('FASC-N is read-only')
        if len(v) != 1 or not v.isdigit():
            raise ValueError('Individual cred issue must be 1 digit long')
        libpivy.piv_fascn_set_indiv_cred_issue(self._ptr, v.encode('ascii'))
    @property
    def person_id(self) -> str:
        return libpivy.piv_fascn_get_person_id(self._ptr).decode('ascii')
    @property
    def org_id(self) -> str:
        return libpivy.piv_fascn_get_org_id(self._ptr).decode('ascii')

    @property
    def org_type(self) -> FascnOC:
        v = libpivy.piv_fascn_get_org_type(self._ptr)
        return FascnOC(value = v)
    @property
    def assoc(self) -> FascnPOA:
        v = libpivy.piv_fascn_get_assoc(self._ptr)
        return FascnPOA(value = v)

    def set_org_id(self, org_type: FascnOC, org_id: str):
        if self._owner:
            raise PermissionError('FASC-N is read-only')
        if len(org_id) != 4 or not org_id.isdigit():
            raise ValueError('Org ID must be 4 digits long')
        libpivy.piv_fascn_set_org_id(self._ptr, org_type.value,
            org_id.encode('ascii'))
    def set_person_id(self, assoc: FascnPOA, person_id: str):
        if self._owner:
            raise PermissionError('FASC-N is read-only')
        if len(person_id) != 10 or not person_id.isdigit():
            raise ValueError('Person ID must be 10 digits long')
        libpivy.piv_fascn_set_person_id(self._ptr, assoc.value,
            person_id.encode('ascii'))

    def __str__(self):
        return libpivy.piv_fascn_to_string(self._ptr).decode('ascii')

    def __repr__(self):
        return '<Fascn(' + self.__str__() + ')>'

