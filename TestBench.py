import os
import sys
import cocotb
from cocotb.triggers import RisingEdge
from cocotb.clock import Clock
from enum import Enum
from cocotb_test.simulator import Verilator
from ascon import ascon_encrypt as custom_software_encrypt

CCW = 32               
CCWD8 = CCW // 8      

class Mode(Enum):
    M_AEAD128_ENC = 1
    M_AEAD128_DEC = 2
    M_HASH        = 4

class Data(Enum):
    D_NONCE = 1
    D_AD    = 2
    D_MSG   = 3 
    D_TAG   = 4


async def send_data_to_hardware(dut, data_in, bdi_type, bdi_eoi):
    dlen = len(data_in)
    d = 0
    data_out = []
    
    if dlen == 0:
        dut.bdi.value = 0
        dut.bdi_valid.value = 0
        dut.bdi_type.value = bdi_type
        if hasattr(dut, 'bdi_len'):
            dut.bdi_len.value = 0
        dut.bdi_eot.value = 1
        dut.bdi_eoi.value = 1 if bdi_eoi else 0
        dut.bdo_ready.value = 1
        await RisingEdge(dut.clk)
        return data_out

    while d < dlen:
        bdi = 0
        bdi_valid = 0
        chunk_bytes = 0
        
        for dd in range(0, CCWD8):
            idx = d + dd
            if idx < dlen:
                bdi |= data_in[idx] << (8 * (CCWD8 - 1 - dd))
                bdi_valid |= 1 << (CCWD8 - 1 - dd)
                chunk_bytes += 1
        
        dut.bdi.value = bdi
        dut.bdi_valid.value = bdi_valid
        dut.bdi_type.value = bdi_type
        
        if hasattr(dut, 'bdi_len'):
            dut.bdi_len.value = chunk_bytes
            
        dut.bdi_eot.value = 1 if (d + CCWD8 >= dlen) else 0
        dut.bdi_eoi.value = 1 if (d + CCWD8 >= dlen and bdi_eoi) else 0
        dut.bdo_ready.value = 1
        
        await RisingEdge(dut.clk)
        
        if int(dut.bdi_valid.value) and int(dut.bdi_ready.value):
            if hasattr(dut, 'bdo_valid') and int(dut.bdo_valid.value):
                bdo_bytes = int(dut.bdo.value).to_bytes(CCWD8, byteorder="big")
                for dd in range(CCWD8):
                    if (bdi_valid & (1 << (CCWD8 - 1 - dd))):
                        data_out.append(bdo_bytes[dd])
            d += CCWD8
            
    dut.bdi.value = 0
    dut.bdi_valid.value = 0
    if hasattr(dut, 'bdi_len'):
        dut.bdi_len.value = 0
    return data_out

async def send_key_to_hardware(dut, key_in):
    k = 0
    while k < 16:
        key_chunk = 0
        for kk in range(0, CCWD8):
            idx = k + kk
            if idx < 16:
                key_chunk |= key_in[idx] << (8 * (CCWD8 - 1 - kk))
        
        dut.key.value = key_chunk
        dut.key_valid.value = 1
        await RisingEdge(dut.clk)
        if int(dut.key_ready.value):
            k += CCWD8
            
    dut.key.value = 0
    dut.key_valid.value = 0

async def receive_tag_from_hardware(dut):
    d = 0
    data_out = []
    while d < 16:
        dut.bdo_ready.value = 1
        await RisingEdge(dut.clk)
        if int(dut.bdo_ready.value) and int(dut.bdo_valid.value) and (int(dut.bdo_type.value) == Data.D_TAG.value):
            bdo_bytes = int(dut.bdo.value).to_bytes(CCWD8, byteorder="big")
            for dd in range(CCWD8):
                if len(data_out) < 16:
                    data_out.append(bdo_bytes[dd])
            d += CCWD8
    dut.bdo_ready.value = 0
    return data_out

async def receive_hash_from_hardware(dut):
    d = 0
    data_out = []
    while d < 32:
        dut.bdo_ready.value = 1
        await RisingEdge(dut.clk)
        if int(dut.bdo_ready.value) and int(dut.bdo_valid.value):
            bdo_bytes = int(dut.bdo.value).to_bytes(CCWD8, byteorder="big")
            for dd in range(CCWD8):
                if len(data_out) < 32:
                    data_out.append(bdo_bytes[dd])
            d += CCWD8
    dut.bdo_ready.value = 0
    return data_out

async def reset_hardware_core(dut):
    dut.rst.value = 1
    dut.mode.value = 0
    dut.key_valid.value = 0
    dut.bdi_valid.value = 0
    dut.bdo_ready.value = 0
    if hasattr(dut, 'bdi_len'):
        dut.bdi_len.value = 0
    for _ in range(5):
        await RisingEdge(dut.clk)
    dut.rst.value = 0
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)


@cocotb.test()
async def run_comprehensive_crypto_test(dut):
    clock = Clock(dut.clk, 1, unit="ns")
    cocotb.start_soon(clock.start(start_high=False))
    

    key        = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    nonce      = bytes.fromhex("101112131415161718191A1B1C1D1E1F")
    associated = b"ascon"
    plaintext  = b"hardware security"

    await reset_hardware_core(dut)
    
    expected_ct, expected_tag = custom_software_encrypt(key, nonce, associated, plaintext)
    dut._log.info(f"SW Expected Ciphertext: {expected_ct.hex().upper()}")
    dut._log.info(f"SW Expected Tag:        {expected_tag.hex().upper()}")

    dut.mode.value = Mode.M_AEAD128_ENC.value
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)

    await send_key_to_hardware(dut, bytearray(key))
    await send_data_to_hardware(dut, bytearray(nonce), Data.D_NONCE.value, (len(associated) == 0) and (len(plaintext) == 0))
    if len(associated) > 0:
        await send_data_to_hardware(dut, bytearray(associated), Data.D_AD.value, (len(plaintext) == 0))
    
    hardware_ct = []
    if len(plaintext) > 0:
        hardware_ct = await send_data_to_hardware(dut, bytearray(plaintext), Data.D_MSG.value, 1)
    hardware_tag = await receive_tag_from_hardware(dut)

    dut._log.info(f"HW Output Ciphertext:  {bytearray(hardware_ct).hex().upper()}")
    dut._log.info(f"HW Output Tag:         {bytearray(hardware_tag).hex().upper()}")

    assert bytearray(hardware_ct) == expected_ct, "Encryption Ciphertext Mismatch"
    assert bytearray(hardware_tag) == expected_tag, "Encryption Tag Mismatch"


    await reset_hardware_core(dut)

    expected_pt = plaintext  
    dut._log.info(f"SW Expected Plaintext:  {expected_pt.hex().upper() if isinstance(expected_pt, bytes) else expected_pt.decode()}")

    dut.mode.value = Mode.M_AEAD128_DEC.value
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)

    await send_key_to_hardware(dut, bytearray(key))
    await send_data_to_hardware(dut, bytearray(nonce), Data.D_NONCE.value, (len(associated) == 0) and (len(expected_ct) == 0))
    if len(associated) > 0:
        await send_data_to_hardware(dut, bytearray(associated), Data.D_AD.value, (len(expected_ct) == 0))
    
    hardware_pt = []
    if len(expected_ct) > 0:
        hardware_pt = await send_data_to_hardware(dut, bytearray(expected_ct), Data.D_MSG.value, 1)
    decryption_tag = await receive_tag_from_hardware(dut)

    dut._log.info(f"HW Output Plaintext:   {bytearray(hardware_pt).hex().upper()}")
    dut._log.info(f"HW Decryption Tag:     {bytearray(decryption_tag).hex().upper()}")

    assert bytearray(hardware_pt) == expected_pt, "Decryption Plaintext Mismatch"
    assert bytearray(decryption_tag) == expected_tag, "Decryption Verification Tag Failed"


    await reset_hardware_core(dut)

    hash_message = b"hardware security"

    dut.mode.value = Mode.M_HASH.value
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)


    await send_data_to_hardware(dut, bytearray(hash_message), Data.D_MSG.value, 1)
    hardware_hash = await receive_hash_from_hardware(dut)

    dut._log.info(f"HW Output Hash Value:  {bytearray(hardware_hash).hex().upper()}")


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    rtl_dir = os.path.join(current_dir, "rtl") 
    top_file = os.path.join(rtl_dir, "ascon_core.sv")

    Verilator(
        verilog_sources=[top_file],
        toplevel="ascon_core",             
        module="mytest",  
        compile_args=[f"-I{rtl_dir}","-DV1","--relative-includes","-Wno-UNOPTFLAT"]            
    ).run()