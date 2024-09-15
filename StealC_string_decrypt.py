"""
idapython script to decrypt strings in StealC.
Reference samples:
19ea28b761e263b381b52bf0674aa36808e79d2e8a98617852a1635afeccdbc2
 72d64cc003975d22b6f5d1d1e7cb7f70e4d698e2b74a1f0f511b8ba60417fe1f 
"""
import ida_xref
import ida_bytes
import ida_ua
import idaapi
import idc


# Address of the XOR function. Replace as needed.
xor_decryption_function_address = 0x17A4610  

def get_push_operand_value(ea):
    insn = ida_ua.insn_t()
    ida_ua.decode_insn(insn, ea)
    if insn.itype == idaapi.NN_push:
        return insn.Op1.value
    return None

def xor_decrypt(key, encrypted):
    decrypted = []
    key_len = len(key)
    for i in range(len(encrypted)):
        decrypted.append(chr(encrypted[i] ^ key[i % key_len]))
    return ''.join(decrypted)

def do_xor(call_addr):
    push1_addr = idc.prev_head(call_addr)
    push2_addr = idc.prev_head(push1_addr)
    push3_addr = idc.prev_head(push2_addr) 

    encrypted_addr = get_push_operand_value(push1_addr)
    key_addr = get_push_operand_value(push2_addr)
    length = get_push_operand_value(push3_addr)

    if key_addr and encrypted_addr and length:
        key = idc.get_strlit_contents(key_addr, -1, idc.STRTYPE_C)
        encrypted = idc.get_bytes(encrypted_addr, length)

        if key and encrypted:
            key = key.decode('ascii')
            key_bytes = [ord(k) for k in key]
            encrypted_bytes = list(encrypted)
            decrypted_string = xor_decrypt(key_bytes, encrypted_bytes)
            idc.set_cmt(call_addr, f"Decrypted string: {decrypted_string}", 0)
            print(f"Decrypted string at 0x{call_addr:X}: {decrypted_string}")
        else:
            print(f"Failed to read key or encrypted string at 0x{call_addr:X}")
    else:
        print(f"Invalid push addresses at 0x{call_addr:X}")

def find_xor_and_decrypt():
    xref = ida_xref.get_first_cref_to(xor_decryption_function_address)
    while xref != idaapi.BADADDR:
        do_xor(xref)
        xref = ida_xref.get_next_cref_to(xor_decryption_function_address, xref)

find_xor_and_decrypt()
