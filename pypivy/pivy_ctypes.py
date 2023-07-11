from ctypes import *
import logging
import enum

"""
Bindings for libpivy, allowing access to PIV tokens and smartcards.

:meta private:
"""

libpivy = CDLL("libpivy.so.1")

#
# errf.h
#
libpivy.warnfx.argtypes = [c_void_p, c_char_p]
libpivy.errfx.argtypes = [c_int, c_void_p, c_char_p]
libpivy.errf_free.argtypes = [c_void_p]

libpivy.errf_caused_by.restype = c_int
libpivy.errf_caused_by.argtypes = [c_void_p, c_char_p]

for x in [libpivy.errf_name, libpivy.errf_message, libpivy.errf_function, libpivy.errf_file]:
    x.restype = c_char_p
    x.argtypes = [c_void_p]
libpivy.errf_errno.argtypes = [c_void_p]
libpivy.errf_errno.restype = c_int
libpivy.errf_line.argtypes = [c_void_p]
libpivy.errf_line.restype = c_uint
libpivy.errf_cause.argtypes = [c_void_p]
libpivy.errf_cause.restype = c_void_p

libpivy._errf.argtypes = [c_char_p, c_void_p, c_char_p, c_char_p, c_uint, c_char_p]
libpivy._errf.restype = c_void_p

libpivy._errfno.argtypes = [c_char_p, c_int, c_char_p, c_char_p, c_uint, c_char_p]
libpivy._errfno.restype = c_void_p

#
# piv.h
#
libpivy.piv_open.restype = c_void_p
libpivy.piv_close.argtypes = [c_void_p]

libpivy.piv_establish_context.argtypes = [c_void_p, c_int]
libpivy.piv_establish_context.restype = c_void_p

libpivy.piv_enumerate.argtypes = [c_void_p, c_void_p]
libpivy.piv_enumerate.restype = c_void_p

libpivy.piv_find.argtypes = [c_void_p, c_void_p, c_size_t, c_void_p]
libpivy.piv_find.restype = c_void_p

libpivy.piv_token_next.argtypes = [c_void_p]
libpivy.piv_token_next.restype = c_void_p

libpivy.piv_release.argtypes = [c_void_p]

libpivy.piv_token_rdrname.argtypes = [c_void_p]
libpivy.piv_token_rdrname.restype = c_char_p

libpivy.piv_token_chuid.argtypes = [c_void_p]
libpivy.piv_token_chuid.restype = c_void_p

libpivy.piv_token_fascn.argtypes = [c_void_p]
libpivy.piv_token_fascn.restype = c_void_p

libpivy.piv_token_guid.argtypes = [c_void_p]
libpivy.piv_token_guid.restype = POINTER(c_ubyte)

libpivy.piv_token_guid_hex.argtypes = [c_void_p]
libpivy.piv_token_guid_hex.restype = c_char_p

libpivy.piv_token_nalgs.argtypes = [c_void_p]
libpivy.piv_token_nalgs.restype = c_size_t

libpivy.piv_token_alg.argtypes = [c_void_p, c_size_t]
libpivy.piv_token_alg.restype = c_int

libpivy.piv_token_default_auth.argtypes = [c_void_p]
libpivy.piv_token_default_auth.restype = c_int

libpivy.piv_token_has_auth.argtypes = [c_void_p, c_int]
libpivy.piv_token_has_auth.restype = c_int

libpivy.piv_token_keyhistory_oncard.argtypes = [c_void_p]
libpivy.piv_token_keyhistory_oncard.restype = c_uint
libpivy.piv_token_keyhistory_offcard.argtypes = [c_void_p]
libpivy.piv_token_keyhistory_offcard.restype = c_uint
libpivy.piv_token_offcard_url.argtypes = [c_void_p]
libpivy.piv_token_offcard_url.restype = c_char_p

libpivy.piv_token_app_label.argtypes = [c_void_p]
libpivy.piv_token_app_label.restype = c_char_p
libpivy.piv_token_app_uri.argtypes = [c_void_p]
libpivy.piv_token_app_uri.restype = c_char_p

libpivy.piv_token_is_ykpiv.argtypes = [c_void_p]
libpivy.piv_token_is_ykpiv.restype = c_int

libpivy.ykpiv_token_version.argtypes = [c_void_p]
libpivy.ykpiv_token_version.restype = POINTER(c_ubyte)

libpivy.ykpiv_version_compare.argtypes = [c_void_p, c_ubyte, c_ubyte, c_ubyte]
libpivy.ykpiv_version_compare.restype = c_int

libpivy.ykpiv_token_has_serial.argtypes = [c_void_p]
libpivy.ykpiv_token_has_serial.restype = c_int

libpivy.ykpiv_token_serial.argtypes = [c_void_p]
libpivy.ykpiv_token_serial.restype = c_uint

libpivy.piv_get_slot.argtypes = [c_void_p]
libpivy.piv_get_slot.restype = c_void_p

libpivy.piv_slot_next.argtypes = [c_void_p, c_void_p]
libpivy.piv_slot_next.restype = c_void_p

libpivy.piv_slot_id.argtypes = [c_void_p]
libpivy.piv_slot_id.restype = c_int

libpivy.piv_slot_alg.argtypes = [c_void_p]
libpivy.piv_slot_alg.restype = c_int

libpivy.piv_slot_subject.argtypes = [c_void_p]
libpivy.piv_slot_subject.restype = c_char_p
libpivy.piv_slot_issuer.argtypes = [c_void_p]
libpivy.piv_slot_issuer.restype = c_char_p
libpivy.piv_slot_serial_hex.argtypes = [c_void_p]
libpivy.piv_slot_serial_hex.restype = c_char_p

libpivy.piv_slot_pubkey.argtypes = [c_void_p]
libpivy.piv_slot_pubkey.restype = c_void_p

libpivy.piv_slot_cert.argtypes = [c_void_p]
libpivy.piv_slot_cert.restype = c_void_p

libpivy.piv_txn_begin.argtypes = [c_void_p]
libpivy.piv_txn_begin.restype = c_void_p

libpivy.piv_txn_end.argtypes = [c_void_p]

libpivy.piv_select.argtypes = [c_void_p]
libpivy.piv_select.restype = c_void_p

libpivy.piv_read_cert.argtypes = [c_void_p, c_int]
libpivy.piv_read_cert.restype = c_void_p

libpivy.piv_read_all_certs.argtypes = [c_void_p]
libpivy.piv_read_all_certs.restype = c_void_p

libpivy.piv_auth_admin.argtypes = [c_void_p, c_void_p, c_size_t, c_int]
libpivy.piv_auth_admin.restype = c_void_p

libpivy.piv_verify_pin.argtypes = [c_void_p, c_int, c_char_p, POINTER(c_uint), c_int]
libpivy.piv_verify_pin.restype = c_void_p

libpivy.piv_clear_pin.argtypes = [c_void_p, c_int]
libpivy.piv_clear_pin.restype = c_void_p

libpivy.piv_auth_key.argtypes = [c_void_p, c_void_p, c_void_p]
libpivy.piv_auth_key.restype = c_void_p

libpivy.piv_chuid_new.restype = c_void_p
libpivy.piv_chuid_clone.argtypes = [c_void_p, c_void_p]
libpivy.piv_chuid_clone.restype = c_void_p
libpivy.piv_chuid_get_fascn.argtypes = [c_void_p]
libpivy.piv_chuid_get_fascn.restype = c_void_p
libpivy.piv_chuid_get_guidhex.argtypes = [c_void_p]
libpivy.piv_chuid_get_guidhex.restype = c_char_p
libpivy.piv_chuid_get_chuuid.argtypes = [c_void_p]
libpivy.piv_chuid_get_chuuid.restype = POINTER(c_ubyte)
libpivy.piv_chuid_get_expiry.argtypes = [c_void_p, POINTER(c_size_t)]
libpivy.piv_chuid_get_expiry.restype = c_void_p
libpivy.piv_chuid_is_expired.argtypes = [c_void_p]
libpivy.piv_chuid_is_expired.restype = c_int
libpivy.piv_chuid_is_signed.argtypes = [c_void_p]
libpivy.piv_chuid_is_signed.restype = c_int
libpivy.piv_chuid_set_random_guid.argtypes = [c_void_p]
libpivy.piv_chuid_set_fascn.argtypes = [c_void_p, c_void_p]
libpivy.piv_chuid_set_guid.argtypes = [c_void_p, c_char_p]
libpivy.piv_chuid_set_expiry.argtypes = [c_void_p, c_char_p, c_size_t]
libpivy.piv_chuid_set_expiry_rel.argtypes = [c_void_p, c_uint]
libpivy.piv_chuid_encode.argtypes = [c_void_p, c_void_p, POINTER(c_size_t)]
libpivy.piv_chuid_encode.restype = c_void_p
libpivy.piv_chuid_decode.argtypes = [c_char_p, c_size_t, c_void_p]
libpivy.piv_chuid_decode.restype = c_void_p
libpivy.piv_chuid_free.argtypes = [c_void_p]

libpivy.piv_fascn_zero.restype = c_void_p
libpivy.piv_fascn_clone.argtypes = [c_void_p]
libpivy.piv_fascn_clone.restype = c_void_p
for x in [libpivy.piv_fascn_get_agency_code, libpivy.piv_fascn_get_system_code, libpivy.piv_fascn_get_cred_number, libpivy.piv_fascn_get_cred_series, libpivy.piv_fascn_get_indiv_cred_issue, libpivy.piv_fascn_get_person_id, libpivy.piv_fascn_get_org_id]:
    x.argtypes = [c_void_p]
    x.restype = c_char_p
for x in [libpivy.piv_fascn_get_org_type, libpivy.piv_fascn_get_assoc]:
    x.argtypes = [c_void_p]
    x.restype = c_int
for x in [libpivy.piv_fascn_set_agency_code, libpivy.piv_fascn_set_system_code, libpivy.piv_fascn_set_cred_number, libpivy.piv_fascn_set_cred_series, libpivy.piv_fascn_set_indiv_cred_issue, libpivy.piv_fascn_set_person_id, libpivy.piv_fascn_set_org_id]:
    x.argtypes = [c_void_p, c_char_p]
libpivy.piv_fascn_set_person_id.argtypes = [c_void_p, c_int, c_char_p]
libpivy.piv_fascn_set_org_id.argtypes = [c_void_p, c_int, c_char_p]
libpivy.piv_fascn_to_string.argtypes = [c_void_p]
libpivy.piv_fascn_to_string.restype = c_char_p
libpivy.piv_fascn_encode.argtypes = [c_void_p, POINTER(c_void_p), POINTER(c_size_t)]
libpivy.piv_fascn_encode.restype = c_void_p
libpivy.piv_fascn_decode.argtypes = [c_char_p, c_size_t, c_void_p]
libpivy.piv_fascn_decode.restype = c_void_p
libpivy.piv_fascn_free.argtypes = [c_void_p]

libpivy.piv_cardcap_new.restype = c_void_p
libpivy.piv_cardcap_free.argtypes = [c_void_p]
libpivy.piv_cardcap_type.argtypes = [c_void_p]
libpivy.piv_cardcap_set_type.argtypes = [c_void_p, c_int]
libpivy.piv_cardcap_manufacturer.argtypes = [c_void_p]
libpivy.piv_cardcap_manufacturer.restype = c_uint
libpivy.piv_cardcap_set_manufacturer.argtypes = [c_void_p, c_uint]
libpivy.piv_cardcap_id_hex.argtypes = [c_void_p]
libpivy.piv_cardcap_id_hex.restype = c_char_p
libpivy.piv_cardcap_set_id.argtypes = [c_void_p, c_char_p, c_size_t]
libpivy.piv_cardcap_set_random_id.argtypes = [c_void_p]
libpivy.piv_cardcap_data_model.argtypes = [c_void_p]
libpivy.piv_cardcap_set_data_model.argtypes = [c_void_p, c_int]
libpivy.piv_read_cardcap.argtypes = [c_void_p, POINTER(c_void_p)]
libpivy.piv_read_cardcap.restype = c_void_p
libpivy.piv_write_cardcap.argtypes = [c_void_p, c_void_p]
libpivy.piv_write_cardcap.restype = c_void_p

for x in [libpivy.piv_pinfo_set_name, libpivy.piv_pinfo_set_affiliation, libpivy.piv_pinfo_set_expiry, libpivy.piv_pinfo_set_serial, libpivy.piv_pinfo_set_issuer, libpivy.piv_pinfo_set_org_line_1, libpivy.piv_pinfo_set_org_line_2]:
    x.argtypes = [c_void_p, c_char_p]
libpivy.piv_pinfo_set_expiry_rel.argtypes = [c_void_p, c_uint]
for x in [libpivy.piv_pinfo_get_name, libpivy.piv_pinfo_get_affiliation, libpivy.piv_pinfo_get_expiry, libpivy.piv_pinfo_get_serial, libpivy.piv_pinfo_get_issuer, libpivy.piv_pinfo_get_org_line_1, libpivy.piv_pinfo_get_org_line_2]:
    x.argtypes = [c_void_p]
    x.restype = c_char_p
libpivy.ykpiv_pinfo_get_admin_key.argtypes = [c_void_p, POINTER(c_size_t)]
libpivy.ykpiv_pinfo_get_admin_key.restype = c_void_p
libpivy.ykpiv_pinfo_set_admin_key.argtypes = [c_void_p, c_char_p, c_size_t]
libpivy.piv_pinfo_new.restype = c_void_p
libpivy.piv_pinfo_free.argtypes = [c_void_p]
libpivy.piv_read_pinfo.argtypes = [c_void_p, POINTER(c_void_p)]
libpivy.piv_read_pinfo.restype = c_void_p
libpivy.piv_write_pinfo.argtypes = [c_void_p, c_void_p]
libpivy.piv_write_pinfo.restype = c_void_p

libpivy.piv_box_new.restype = c_void_p
libpivy.piv_box_free.argtypes = [c_void_p]
libpivy.piv_box_clone.argtypes = [c_void_p]
libpivy.piv_box_clone.restype = c_void_p
libpivy.piv_box_set_data.argtypes = [c_void_p, c_char_p, c_size_t]
libpivy.piv_box_set_data.restype = c_void_p
libpivy.piv_box_set_datab.argtypes = [c_void_p, c_void_p]
libpivy.piv_box_set_datab.restype = c_void_p
libpivy.piv_box_seal.argtypes = [c_void_p, c_void_p, c_void_p]
libpivy.piv_box_seal.restype = c_void_p
libpivy.piv_box_seal_offline.argtypes = [c_void_p, c_void_p]
libpivy.piv_box_seal_offline.restype = c_void_p
libpivy.piv_box_has_guidslot.argtypes = [c_void_p]
libpivy.piv_box_guid.argtypes = [c_void_p]
libpivy.piv_box_guid.restype = POINTER(c_ubyte)
libpivy.piv_box_guid_hex.argtypes = [c_void_p]
libpivy.piv_box_guid_hex.restype = c_char_p
libpivy.piv_box_slot.argtypes = [c_void_p]
libpivy.piv_box_pubkey.argtypes = [c_void_p]
libpivy.piv_box_pubkey.restype = c_void_p
libpivy.piv_box_ephem_pubkey.argtypes = [c_void_p]
libpivy.piv_box_ephem_pubkey.restype = c_void_p
libpivy.piv_box_cipher.argtypes = [c_void_p]
libpivy.piv_box_cipher.restype = c_char_p
libpivy.piv_box_kdf.argtypes = [c_void_p]
libpivy.piv_box_kdf.restype = c_char_p
libpivy.piv_box_encsize.argtypes = [c_void_p]
libpivy.piv_box_encsize.restype = c_size_t
libpivy.piv_box_sealed.argtypes = [c_void_p]
libpivy.piv_box_nonce_size.argtypes = [c_void_p]
libpivy.piv_box_nonce_size.restype = c_size_t
libpivy.piv_box_version.argtypes = [c_void_p]
libpivy.piv_box_version.restype = c_uint
libpivy.piv_box_set_guid.argtypes = [c_void_p, c_char_p, c_size_t]
libpivy.piv_box_set_slot.argtypes = [c_void_p, c_int]
libpivy.piv_box_find_token.argtypes = [c_void_p, c_void_p, POINTER(c_void_p), POINTER(c_void_p)]
libpivy.piv_box_find_token.restype = c_void_p
libpivy.piv_box_take_data.argtypes = [c_void_p, POINTER(c_void_p), POINTER(c_size_t)]
libpivy.piv_box_take_data.restype = c_void_p
libpivy.piv_box_take_datab.argtypes = [c_void_p, POINTER(c_void_p)]
libpivy.piv_box_take_datab.restype = c_void_p
libpivy.piv_box_open.argtypes = [c_void_p, c_void_p, c_void_p]
libpivy.piv_box_open.restype = c_void_p

#
# ebox.h
#
libpivy.ebox_tpl_alloc.restype = c_void_p
libpivy.ebox_tpl_free.argtypes = [c_void_p]
libpivy.ebox_tpl_config_alloc.argtypes = [c_int]
libpivy.ebox_tpl_config_alloc.restype = c_void_p
libpivy.ebox_tpl_config_free.argtypes = [c_void_p]
libpivy.ebox_tpl_part_alloc.argtypes = [c_void_p, c_size_t, c_int, c_void_p]
libpivy.ebox_tpl_part_alloc.restype = c_void_p
libpivy.ebox_tpl_part_free.argtypes = [c_void_p]

libpivy.ebox_tpl_version.argtypes = [c_void_p]
libpivy.ebox_tpl_version.restype = c_uint
libpivy.ebox_tpl_clone.argtypes = [c_void_p]
libpivy.ebox_tpl_clone.restype = c_void_p

libpivy.ebox_tpl_next_config.argtypes = [c_void_p, c_void_p]
libpivy.ebox_tpl_next_config.restype = c_void_p
libpivy.ebox_tpl_config_type.argtypes = [c_void_p]
libpivy.ebox_tpl_config_n.argtypes = [c_void_p]
libpivy.ebox_tpl_config_n.restype = c_uint

libpivy.ebox_tpl_config_next_part.argtypes = [c_void_p, c_void_p]
libpivy.ebox_tpl_config_next_part.restype = c_void_p
libpivy.ebox_tpl_part_name.argtypes = [c_void_p]
libpivy.ebox_tpl_part_name.restype = c_char_p
libpivy.ebox_tpl_part_set_name.argtypes = [c_void_p, c_char_p]
libpivy.ebox_tpl_part_cak.argtypes = [c_void_p]
libpivy.ebox_tpl_part_cak.restype = c_void_p
libpivy.ebox_tpl_part_pubkey.argtypes = [c_void_p]
libpivy.ebox_tpl_part_pubkey.restype = c_void_p
libpivy.ebox_tpl_part_slot.argtypes = [c_void_p]
libpivy.ebox_tpl_part_guid.argtypes = [c_void_p]
libpivy.ebox_tpl_part_guid.restype = c_void_p

libpivy.ebox_tpl.argtypes = [c_void_p]
libpivy.ebox_tpl.restype = c_void_p
libpivy.ebox_config_tpl.argtypes = [c_void_p]
libpivy.ebox_config_tpl.restype = c_void_p
libpivy.ebox_part_tpl.argtypes = [c_void_p]
libpivy.ebox_part_tpl.restype = c_void_p
libpivy.ebox_version.argtypes = [c_void_p]
libpivy.ebox_version.restype = c_uint
libpivy.ebox_type.argtypes = [c_void_p]
libpivy.ebox_type.restype = c_int
libpivy.ebox_is_unlocked.argtypes = [c_void_p]

libpivy.ebox_free.argtypes = [c_void_p]
libpivy.ebox_challenge_free.argtypes = [c_void_p]

libpivy.ebox_stream_new.argtypes = [c_void_p, POINTER(c_void_p)]
libpivy.ebox_stream_new.restype = c_void_p
libpivy.ebox_stream_free.argtypes = [c_void_p]

libpivy.ebox_stream_chunk_free.argtypes = [c_void_p]

libpivy.sshbuf_put_ebox_tpl.argtypes = [c_void_p, c_void_p]
libpivy.sshbuf_put_ebox_tpl.restype = c_void_p
libpivy.sshbuf_get_ebox_tpl.argtypes = [c_void_p, POINTER(c_void_p)]
libpivy.sshbuf_get_ebox_tpl.restype = c_void_p

#
# libssh misc
#
libpivy.ssh_err.argtypes = [c_int]
libpivy.ssh_err.restype = c_char_p

#
# sshkey.h
#

libpivy.sshkey_new.argtypes = [c_int]
libpivy.sshkey_new.restype = c_void_p
libpivy.sshkey_free.argtypes = [c_void_p]
libpivy.sshkey_type.argtypes = [c_void_p]
libpivy.sshkey_type.restype = c_char_p
libpivy.sshkey_size.argtypes = [c_void_p]
libpivy.sshkey_size.restype = c_uint

libpivy.sshkey_fingerprint.argtypes = [c_void_p, c_int, c_int]
libpivy.sshkey_fingerprint.restype = c_char_p

libpivy.sshkey_equal_public.argtypes = [c_void_p, c_void_p]
libpivy.sshkey_equal_public.restype = c_int

libpivy.sshkey_get_sigtype.argtypes = [c_char_p, c_size_t, POINTER(c_char_p)]
libpivy.sshkey_get_sigtype.restype = c_int

libpivy.sshkey_verify.argtypes = [c_void_p, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_uint, c_void_p]

libpivy.sshkey_read.argtypes = [c_void_p, POINTER(c_void_p)]
libpivy.sshkey_read.restype = c_int

libpivy.sshkey_format_text.argtypes = [c_void_p, c_void_p]

libpivy.sshkey_from_private.argtypes = [c_void_p, POINTER(c_void_p)]

#
# sshbuf.h
#
libpivy.sshbuf_new.restype = c_void_p
libpivy.sshbuf_from.argtypes = [c_void_p, c_size_t]
libpivy.sshbuf_from.restype = c_void_p
libpivy.sshbuf_free.argtypes = [c_void_p]
libpivy.sshbuf_reset.argtypes = [c_void_p]
libpivy.sshbuf_put.argtypes = [c_void_p, c_char_p, c_size_t]
libpivy.sshbuf_get.argtypes = [c_void_p, c_char_p, c_size_t]
libpivy.sshbuf_len.argtypes = [c_void_p]
libpivy.sshbuf_len.restype = c_size_t
libpivy.sshbuf_avail.argtypes = [c_void_p]
libpivy.sshbuf_avail.restype = c_size_t
libpivy.sshbuf_ptr.argtypes = [c_void_p]
libpivy.sshbuf_ptr.restype = c_void_p
libpivy.sshbuf_putb.argtypes = [c_void_p, c_void_p]
libpivy.sshbuf_get_u64.argtypes = [c_void_p, POINTER(c_ulonglong)]
libpivy.sshbuf_get_u32.argtypes = [c_void_p, POINTER(c_uint)]
libpivy.sshbuf_get_u16.argtypes = [c_void_p, POINTER(c_ushort)]
libpivy.sshbuf_get_u8.argtypes = [c_void_p, POINTER(c_ubyte)]
libpivy.sshbuf_put_u64.argtypes = [c_void_p, c_ulonglong]
libpivy.sshbuf_put_u32.argtypes = [c_void_p, c_uint]
libpivy.sshbuf_put_u16.argtypes = [c_void_p, c_ushort]
libpivy.sshbuf_put_u8.argtypes = [c_void_p, c_ubyte]
libpivy.sshbuf_dtob16.argtypes = [c_void_p]
libpivy.sshbuf_dtob16.restype = c_char_p
libpivy.sshbuf_dtob64_string.argtypes = [c_void_p, c_int]
libpivy.sshbuf_dtob64_string.restype = c_char_p
libpivy.sshkey_sig_from_asn1.argtypes = [c_void_p, c_int, c_void_p, c_size_t, c_void_p]
libpivy.sshkey_sig_to_asn1.argtypes = [c_void_p, c_void_p, POINTER(c_int), c_void_p]
libpivy.sshbuf_b64tod.argtypes = [c_void_p, c_char_p]

#
# piv-ca.h
#
libpivy.scope_new_root.restype = c_void_p
libpivy.scope_free_root.argtypes = [c_void_p]
libpivy.ca_close.argtypes = [c_void_p]
libpivy.cert_tpl_name.argtypes = [c_void_p]
libpivy.cert_tpl_name.restype = c_char_p
libpivy.cert_tpl_help.argtypes = [c_void_p]
libpivy.cert_tpl_help.restype = c_char_p
libpivy.cert_tpl_find.argtypes = [c_char_p]
libpivy.cert_tpl_find.restype = c_void_p
libpivy.cert_tpl_first.restype = c_void_p
libpivy.cert_tpl_next.argtypes = [c_void_p]
libpivy.cert_tpl_next.restype = c_void_p
libpivy.ca_open.argtypes = [c_char_p, POINTER(c_void_p)]
libpivy.ca_open.restype = c_void_p

libpivy.ca_slug.argtypes = [c_void_p]
libpivy.ca_slug.restype = c_char_p
libpivy.ca_guidhex.argtypes = [c_void_p]
libpivy.ca_guidhex.restype = c_char_p

libpivy.ca_pubkey.argtypes = [c_void_p]
libpivy.ca_pubkey.restype = c_void_p
libpivy.ca_cak.argtypes = [c_void_p]
libpivy.ca_cak.restype = c_void_p
libpivy.ca_dn.argtypes = [c_void_p]
libpivy.ca_dn.restype = c_char_p

libpivy.ca_open_session.argtypes = [c_void_p, POINTER(c_void_p)]
libpivy.ca_open_session.restype = c_void_p

libpivy.ca_session_authed.argtypes = [c_void_p]
libpivy.ca_session_auth_type.argtypes = [c_void_p]
libpivy.ca_session_auth.argtypes = [c_void_p, c_int, c_char_p]
libpivy.ca_session_auth.restype = c_void_p
libpivy.ca_rotate_pin.argtypes = [c_void_p]
libpivy.ca_rotate_pin.restype = c_void_p

libpivy.ca_crl_uri_count.argtypes = [c_void_p]
libpivy.ca_crl_uri.argtypes = [c_void_p, c_uint]
libpivy.ca_crl_uri.restype = c_char_p
libpivy.ca_ocsp_uri_count.argtypes = [c_void_p]
libpivy.ca_ocsp_uri.argtypes = [c_void_p, c_uint]
libpivy.ca_ocsp_uri.restype = c_char_p
libpivy.ca_aia_uri_count.argtypes = [c_void_p]
libpivy.ca_aia_uri.argtypes = [c_void_p, c_uint]
libpivy.ca_aia_uri.restype = c_char_p

libpivy.ca_get_ebox.argtypes = [c_void_p, c_int]
libpivy.ca_get_ebox.restype = c_void_p

libpivy.ca_get_ebox_tpl.argtypes = [c_void_p, c_int]
libpivy.ca_get_ebox_tpl.restype = c_char_p
libpivy.ca_set_ebox_tpl.argtypes = [c_void_p, c_int, c_char_p]
libpivy.ca_set_ebox_tpl.restype = c_void_p
libpivy.ca_get_ebox_tpl_name.argtypes = [c_void_p, c_char_p]
libpivy.ca_get_ebox_tpl_name.restype = c_void_p
libpivy.ca_set_ebox_tpl_name.argtypes = [c_void_p, c_char_p, c_void_p]

#
# openssl bits
#
libpivy.X509_new.restype = c_void_p
libpivy.X509_free.argtypes = [c_void_p]
libpivy.X509_REQ_new.restype = c_void_p
libpivy.X509_REQ_free.argtypes = [c_void_p]
libpivy.X509_CRL_new.restype = c_void_p
libpivy.X509_CRL_free.argtypes = [c_void_p]
for x in [libpivy.X509_to_der, libpivy.X509_REQ_to_der, libpivy.X509_CRL_to_der]:
    x.argtypes = [c_void_p, POINTER(c_void_p), POINTER(c_size_t)]
    x.restype = c_void_p
for x in [libpivy.X509_from_der, libpivy.X509_REQ_from_der, libpivy.X509_CRL_from_der]:
    x.argtypes = [c_char_p, c_size_t, POINTER(c_void_p)]
    x.restype = c_void_p

#
# use the same malloc/free in the global namespace as python
#
pythonapi.malloc.restype = c_void_p
pythonapi.free.argtypes = [c_void_p]

# bunyan
bunyan_printer = CFUNCTYPE(None, c_int, c_char_p)
libpivy.bunyan_set_printer.argtypes = [bunyan_printer, c_int]

log = logging.getLogger('libpivy')
class BunyanLogLevel(enum.Enum):
    FATAL = 60
    ERROR = 50
    WARN = 40
    INFO = 30
    DEBUG = 20
    TRACE = 10

    @property
    def logging_level(self):
        if self == BunyanLogLevel.FATAL:
            return logging.CRITICAL
        elif self == BunyanLogLevel.ERROR:
            return logging.ERROR
        elif self == BunyanLogLevel.WARN:
            return logging.WARNING
        elif self == BunyanLogLevel.INFO:
            return logging.INFO
        elif self == BunyanLogLevel.DEBUG:
            return logging.DEBUG
        else:
            return logging.NOTSET

def py_bunyan_printer(ilevel, msg):
    level = BunyanLogLevel(value = ilevel)
    log.log(level = level.logging_level, msg = msg.decode('utf-8'))
my_printer = bunyan_printer(py_bunyan_printer)
libpivy.bunyan_init()
libpivy.bunyan_set_printer(my_printer, 1)
