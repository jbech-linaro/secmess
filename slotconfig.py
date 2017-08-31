#!/usr/bin/python2
import hashlib

DEBUG = 0

ALWAYS =  0b0000
NEVER =   0b0010
ENCRYPT = 0b0100

DERIVE_TARGET =  0b0010
DERIVE_PARENT =  0b0011
DERIVE_AUTH_MAC = 0b1000

def foo():
    MAC_Challenge = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
    RandOut       = "ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000"
    NumIn         = "0101010101010101010101010101010101010101010101010101010101010101"
    Opcode = 0x16
    Mode = 0x0
    LSB_param2 = 0x0

    print("Hmac")
    print("RandOut: %s" % RandOut)

    m = hashlib.sha256()
    m.update(MAC_Challenge.decode('hex'))
    m.update(NumIn.decode('hex'))
    m.update(chr(Opcode))
    m.update(chr(Mode))
    m.update(chr(LSB_param2))
    print(m.hexdigest())

    print("abc".encode('hex'))
    print(chr(0x31))

def gen_key(SlotConfig=0, ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=0, WriteKey=0, WriteConfig=0):
    if SlotConfig < 0 or SlotConfig > 0xf:
        print("Error: Invalid config: %d" % SlotConfig)
        exit(0)

    if ReadKey < 0 or ReadKey > 0xf:
        print("Error: Invalid ReadKey: %d" % ReadKey)
        exit(0)

    if SingleUse != 0 and SingleUse != 1:
        print("Error: Invalid SingleUse: %d" % SingleUse)
        exit(0)

    if EncryptedRead != 0 and EncryptedRead != 1:
        print("Error: Invalid EncryptedRead: %d" % EncryptedRead)
        exit(0)

    if IsSecret != 0 and IsSecret != 1:
        print("Error: Invalid IsSecret: %d" % IsSecret)
        exit(0)

    if WriteKey < 0 or WriteKey > 0xf:
        print("Error: Invalid WriteKey: %d" % WriteKey)
        exit(0)

    if WriteConfig < 0 or WriteConfig > 0xf:
        print("Error: Invalid WriteConfig: %d" % WriteConfig)
        exit(0)

    config_value =  hex(WriteConfig << 12 | WriteKey << 8 |
                IsSecret << 7 | EncryptedRead << 6 | SingleUse << 5 | CheckOnly << 4 | ReadKey)

    if DEBUG > 1:
        print("SlotConfig: %d" % SlotConfig)
        print("ReadKey: %d" % ReadKey)
        print("SingleUse: %d" % SingleUse)
        print("EncryptedRead: %d" % EncryptedRead)
        print("IsSecret: %d" % IsSecret)
        print("WriteKey: %d" % WriteKey)
        print("WriteConfig: %d" % WriteConfig)
    if DEBUG > 0:
        print("Key[%02d]: %s" % (SlotConfig, config_value))

    return int(config_value, 16)

def SLOT_CONFIG_ADDR(slotnbr):
    addr = 0x5;
    if slotnbr % 2:
        slotnbr = slotnbr - 1
    slotnbr >>= 1
    return addr + slotnbr

def print_c_code(k_low, k_high, k_low_nbr, k_high_nbr):
    byte0 = k_low & 0xff;
    byte1 = k_low >> 8;
    byte2 = k_high & 0xff;
    byte3 = k_high >> 8;

    print("{")
    print("     uint8_t keypair_%s_%s[] = { 0x%02x, 0x%02x,   0x%02x, 0x%02x };" %
            (k_low_nbr, k_high_nbr, byte0, byte1, byte2, byte3))
    print("     cmd_write(ioif, ZONE_CONFIG, 0x%02x, keypair_%s_%s, sizeof(keypair_%s_%s));" %
            (SLOT_CONFIG_ADDR(k_low_nbr), k_low_nbr, k_high_nbr, k_low_nbr, k_high_nbr))
    print("}\n")

def main():
    print("ATSHA204A slot config generator")
    k0 = gen_key(0,  ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=1, WriteKey=0, WriteConfig=NEVER)
    k1 = gen_key(1,  ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=1, WriteKey=0, WriteConfig=NEVER|DERIVE_TARGET)
    print_c_code(k0, k1, 0, 1)

    k2 = gen_key(2,  ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=1, WriteKey=0, WriteConfig=NEVER)
    k3 = gen_key(3,  ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=1, WriteKey=0, WriteConfig=NEVER|DERIVE_TARGET)
    print_c_code(k2, k3, 2, 3)

    k4 = gen_key(4,  ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=1, WriteKey=0, WriteConfig=NEVER)
    k5 = gen_key(5,  ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=1, WriteKey=0, WriteConfig=NEVER|DERIVE_TARGET)
    print_c_code(k4, k5, 4, 5)

    k6 = gen_key(6,  ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=1, WriteKey=6, WriteConfig=ENCRYPT)
    k7 = gen_key(7,  ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=1, WriteKey=7, WriteConfig=ENCRYPT)
    print_c_code(k6, k7, 6, 7)

    k8 = gen_key(8,  ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=1, WriteKey=0, WriteConfig=NEVER)
    k9 = gen_key(9,  ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=1, WriteKey=0, WriteConfig=NEVER)
    print_c_code(k8, k9, 8, 9)

    k10 = gen_key(10, ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=1, WriteKey=0, WriteConfig=NEVER)
    k11 = gen_key(11, ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=1, WriteKey=0, WriteConfig=NEVER)
    print_c_code(k10, k11, 10, 11)

    k12 = gen_key(12, ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=0, WriteKey=0, WriteConfig=ALWAYS)
    k13 = gen_key(13, ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=0, WriteKey=0, WriteConfig=ALWAYS)
    print_c_code(k12, k13, 12, 13)

    k14 = gen_key(14, ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=0, WriteKey=0, WriteConfig=NEVER)
    k15 = gen_key(15, ReadKey=0, CheckOnly=0, SingleUse=0, EncryptedRead=0, IsSecret=0, WriteKey=0, WriteConfig=NEVER)
    print_c_code(k14, k15, 14, 15)

if __name__ == "__main__":
    main()
