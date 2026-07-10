#!/usr/bin/env python3
"""
God Eater Resurrection - SECURE.BIN encrypt/decrypt tool and reigon porter
==========================================================

DISCLAIMER: Generative AI was used to assist in the RE process and the writing this tool.
It is, regardless, fully functional. I, Suletta, take full responsibility for any errors in the code.

Reverse-engineered from GER.exe (source file: src\\lib\\denc.c).
The algorithm and key-derivation formula below have been verified against real save data. 
(SECURE.BIN + a live-memory plaintext capture)

USAGE
-----
  Decrypt (key is read automatically from the file's own trailer):
      python3 GERSaveCryptTool.py decrypt SECURE.BIN output.bin

  Encrypt (key is derived automatically from RtcHash at offset 0x40):
      python3 GERSaveCryptTool.py encrypt plain.bin SECURE_new.BIN

  Encrypt and auto-fix checksums after editing fields:
      python3 GERSaveCryptTool.py encrypt plain.bin SECURE_new.BIN --fix-checksums

  Inspect / fix checksums on a plaintext file without encrypting:
      python3 GERSaveCryptTool.py checksums plain.bin
      python3 GERSaveCryptTool.py checksums plain.bin --fix plain_fixed.bin

  Inspect known fields in a plaintext file:
      python3 GERSaveCryptTool.py info plain.bin
      
  Port Region (-to dictates arrival, pick the one OPPOSITE of your save, JP or ENG.)
      python3 GERSaveCryptTool.py -to JP SECURE.BIN output.bin
"""

import sys
import struct
import argparse
import numpy as np

MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF
SAVE_SIZE = 0xdb050          # total file size, plaintext or ciphertext
BODY_SIZE = SAVE_SIZE - 8    # bytes actually run through the cipher
UNIVERSAL_CONSTANT = 0x8a51891ce32973e4
CHKSUM_OFFSET = 0x10
EZHASH_OFFSET = 0x14
RTCHASH_OFFSET = 0x40        # key-derivation seed AND source of the trailer
TRAILER_OFFSET = BODY_SIZE   # 0xdb048 - unencrypted copy of RtcHash, appended

# Baked-in region-format data for the Vita release, so port-region works
# out of the box for JP<->Global without needing external blank-save files.
# Derived by diffing freshly-initialized JP and Global saves and excluding
# key-material offsets (see build_region_mask). Covers the item/equipment/
# bullet catalog-name cache and the quick-chat UI text block - the fields
# confirmed (by direct in-game testing) to actually matter for a load to
# succeed cross-region. Not exhaustive - if a future platform/region needs
# fields outside this set, fall back to --source-blank/--target-blank.
VITA_REGION_RANGES = [(87, 98), (270, 293), (390, 401), (510, 527), (630, 647), (750, 773), (4110, 4139), (4230, 4259), (4350, 4367), (4470, 4484), (4590, 4613), (4710, 4736), (5070, 5090), (5176, 5195), (6320, 6340), (7464, 7483), (8608, 8628), (9752, 9769), (10896, 10914), (12040, 12057), (13184, 13202), (14328, 14344), (15472, 15492), (93104, 93104), (93106, 93106), (93108, 93108), (93110, 93122), (93216, 93216), (93320, 93320), (131342, 131365), (131462, 131473), (131582, 131599), (131702, 131719), (131822, 131845), (135182, 135211), (135302, 135331), (135422, 135439), (135542, 135556), (135662, 135685), (135782, 135808), (136142, 136162), (136248, 136267), (137392, 137412), (138536, 138555), (139680, 139700), (140824, 140841), (141968, 141986), (143112, 143129), (144256, 144274), (145400, 145416), (146544, 146564), (224176, 224176), (224178, 224178), (224180, 224180), (224182, 224194), (448300, 448312), (448408, 448427), (448516, 448536), (448624, 448643), (448732, 448752), (448840, 448860), (448948, 448969), (449056, 449076), (449164, 449185), (449272, 449291), (449380, 449399), (449488, 449508), (449596, 449615), (449704, 449724), (449812, 449829), (449920, 449938), (450028, 450045), (450136, 450154), (450244, 450260), (450352, 450372), (450460, 450479), (450568, 450588), (450676, 450695), (450784, 450804), (450892, 450912), (451000, 451020), (451108, 451128), (451216, 451236), (451324, 451341), (451432, 451449), (451540, 451557), (451648, 451665), (451756, 451774), (451864, 451878), (451972, 451987), (452080, 452094), (452188, 452203), (452296, 452316), (452404, 452424), (452512, 452532), (452620, 452640), (452728, 452757), (475596, 475596), (475740, 475755), (475760, 475763), (476140, 476140), (476142, 476142), (476144, 476144), (476180, 476199), (476288, 476308), (476396, 476415), (476504, 476524), (476612, 476629), (476720, 476738), (476828, 476845), (476936, 476954), (477044, 477060), (477152, 477172), (609776, 609776), (647896, 647905), (647934, 647953), (647972, 647981), (648010, 648025), (648048, 648063), (648086, 648097), (648124, 648145), (648162, 648177), (648200, 648225), (648238, 648251), (648348, 648348), (648350, 648350), (652704, 652704), (652706, 652706), (652708, 652708), (652710, 652710), (652712, 652712), (652714, 652714), (652784, 652784), (652786, 652786), (652788, 652788), (652790, 652790), (652792, 652792), (652794, 652794), (652796, 652796), (652798, 652798), (652800, 652800), (652802, 652802), (652804, 652804), (652806, 652806), (652808, 652808), (652810, 652810), (652812, 652812), (652814, 652814), (652816, 652816), (652818, 652818), (652820, 652820), (652822, 652822), (652864, 652864), (652866, 652866), (652868, 652868), (652870, 652870), (652872, 652872), (652874, 652874), (652876, 652876), (652878, 652878), (652880, 652880), (652882, 652882), (652884, 652884), (652886, 652886), (652888, 652888), (652890, 652890), (652892, 652892), (652944, 652944), (652946, 652946), (652948, 652948), (652950, 652950), (652952, 652952), (652954, 652954), (652956, 652956), (652958, 652958), (652960, 652960), (652962, 652962), (652964, 652964), (652966, 652966), (652968, 652968), (652970, 652970), (652972, 652972), (652974, 652974), (652976, 652976), (652978, 652978), (653024, 653024), (653026, 653026), (653028, 653028), (653030, 653030), (653032, 653032), (653034, 653034), (653036, 653036), (653038, 653038), (653040, 653040), (653042, 653042), (653044, 653044), (653104, 653104), (653106, 653106), (653108, 653108), (653110, 653110), (653112, 653112), (653114, 653114), (653116, 653116), (653184, 653184), (653186, 653186), (653188, 653188), (653190, 653190), (653192, 653192), (653194, 653194), (653196, 653196), (653198, 653198), (653200, 653200), (653202, 653202), (653204, 653204), (653206, 653206), (653208, 653208), (653264, 653264), (653266, 653266), (653268, 653268), (653270, 653270), (653272, 653272), (653274, 653274), (653276, 653276), (653278, 653278), (653280, 653280), (653282, 653282), (653284, 653284), (653286, 653286), (653288, 653288), (653290, 653290), (653292, 653292), (653294, 653294), (653296, 653296), (653298, 653298), (653300, 653300), (653302, 653302), (653304, 653304), (653306, 653306), (653308, 653308), (653344, 653344), (653346, 653346), (653348, 653348), (653350, 653350), (653352, 653352), (653354, 653354), (653356, 653356), (653358, 653358), (653360, 653360), (653362, 653362), (653364, 653364), (653366, 653366), (653368, 653368), (653370, 653370), (653372, 653372), (653374, 653374), (653376, 653376), (653378, 653378), (653380, 653380), (653382, 653382), (653424, 653424), (653426, 653426), (653428, 653428), (653430, 653430), (653432, 653432), (653434, 653434)]

VITA_REGION_DATA = {
    'jp': bytes.fromhex('310000000000000000000000e382b9e382bfe383b3e382b0e383ace3838de383bce38389e59b9ee5bea9e98ca0000000efbcafefbca7efbc9ae59b9ee5bea9e79083efbcafefbca7efbc9ae59b9ee5bea9e69fb1e3839be383bce383abe38389e38388e383a9e38383e38397efbca6e588b6e5bc8fe4b88ae8a1a3e38080e382b3e38390e383abe38388efbca6e588b6e5bc8fe4b88be8a1a3e38080e382b3e38390e383abe38388e38397e383ade38388e382bfe382a4e38397e3838ae382a4e38395e38080e5ba8fefbc95efbc90e59e8be6a99fe996a2e7a0b2e38080e5ba8fe6b18ee794a8e38390e38383e382afe383a9e383bce38080e5ba8fe38380e3839fe383bce38387e38390e382a4e382b9e9809ae5b8b8e5bcbeefbc9ae7828e0000000000e9809ae5b8b8e5bcbeefbc9ae6b0b7000000000000e9809ae5b8b8e5bcbeefbc9ae99bb70000000000e9809ae5b8b8e5bcbeefbc9ae7a59e000000000000e9809ae5b8b8e5bcbeefbc9ae7828ee78886e9809ae5b8b8e5bcbeefbc9ae6b0b7e7888600e9809ae5b8b8e5bcbeefbc9ae99bb7e78886e9809ae5b8b8e5bcbeefbc9ae7a59ee7888600e980a3e5b084e5bcbe0000000000000000e59b9ee5bea9e5bcbeefbc9aefbca1efbcb3000000000000000000000000000000000000000301e382b9e382bfe383b3e382b0e383ace3838de383bce38389e59b9ee5bea9e98ca0000000efbcafefbca7efbc9ae59b9ee5bea9e79083efbcafefbca7efbc9ae59b9ee5bea9e69fb1e3839be383bce383abe38389e38388e383a9e38383e38397efbca6e588b6e5bc8fe4b88ae8a1a3e38080e382b3e38390e383abe38388efbca6e588b6e5bc8fe4b88be8a1a3e38080e382b3e38390e383abe38388e38397e383ade38388e382bfe382a4e38397e3838ae382a4e38395e38080e5ba8fefbc95efbc90e59e8be6a99fe996a2e7a0b2e38080e5ba8fe6b18ee794a8e38390e38383e382afe383a9e383bce38080e5ba8fe38380e3839fe383bce38387e38390e382a4e382b9e9809ae5b8b8e5bcbeefbc9ae7828e0000000000e9809ae5b8b8e5bcbeefbc9ae6b0b7000000000000e9809ae5b8b8e5bcbeefbc9ae99bb70000000000e9809ae5b8b8e5bcbeefbc9ae7a59e000000000000e9809ae5b8b8e5bcbeefbc9ae7828ee78886e9809ae5b8b8e5bcbeefbc9ae6b0b7e7888600e9809ae5b8b8e5bcbeefbc9ae99bb7e78886e9809ae5b8b8e5bcbeefbc9ae7a59ee7888600e980a3e5b084e5bcbe0000000000000000e59b9ee5bea9e5bcbeefbc9aefbca1efbcb300000000000000000000000000000000000000e78b99e69283e5bcbe00000000e78b99e69283e5bcbeefbc9ae7828e0000000000e78b99e69283e5bcbeefbc9ae6b0b7000000000000e78b99e69283e5bcbeefbc9ae99bb70000000000e78b99e69283e5bcbeefbc9ae7a59e000000000000e78b99e69283e5bcbeefbc9ae7828ee78886000000e78b99e69283e5bcbeefbc9ae6b0b7e7888600000000e78b99e69283e5bcbeefbc9ae99bb7e78886000000e78b99e69283e5bcbeefbc9ae7a59ee7888600000000e59b9ee5bea9e5bcbeefbc9aefbcb3efbcae0000e9809ae5b8b8e5bcbeefbc9ae7828e0000000000e9809ae5b8b8e5bcbeefbc9ae6b0b7000000000000e9809ae5b8b8e5bcbeefbc9ae99bb70000000000e9809ae5b8b8e5bcbeefbc9ae7a59e000000000000e9809ae5b8b8e5bcbeefbc9ae7828ee78886e9809ae5b8b8e5bcbeefbc9ae6b0b7e7888600e9809ae5b8b8e5bcbeefbc9ae99bb7e78886e9809ae5b8b8e5bcbeefbc9ae7a59ee7888600e980a3e5b084e5bcbe0000000000000000e59b9ee5bea9e5bcbeefbc9aefbca1efbcb3000000e8bfbde5b0bee5bcbeefbc9ae7828e0000000000e8bfbde5b0bee5bcbeefbc9ae6b0b7000000000000e8bfbde5b0bee5bcbeefbc9ae99bb70000000000e8bfbde5b0bee5bcbeefbc9ae7a59e000000000000e383ade382b1e38383e38388e5bcbeefbc9ae7828ee383ade382b1e38383e38388e5bcbeefbc9ae6b0b7e383ade382b1e38383e38388e5bcbeefbc9ae99bb7e383ade382b1e38383e38388e5bcbeefbc9ae7a59ee383a2e383abe382bfe383bcefbc9ae7828ee383a2e383abe382bfe383bcefbc9ae6b0b7e383a2e383abe382bfe383bcefbc9ae99bb7e383a2e383abe382bfe383bcefbc9ae7a59ee59b9ee5bea9e5bcbeefbc9aefbca2efbcac00e695a3e5bcbeefbc9ae7828e000000e695a3e5bcbeefbc9ae6b0b700000000e695a3e5bcbeefbc9ae99bb7000000e695a3e5bcbeefbc9ae7a59e00000000e382b9e383a9e38383e382b0e5bcbeefbc9ae7828ee382b9e383a9e38383e382b0e5bcbeefbc9ae6b0b7e382b9e383a9e38383e382b0e5bcbeefbc9ae99bb7e382b9e383a9e38383e382b0e5bcbeefbc9ae7a59ee59b9ee5bea9e382a8e3839fe38383e382bfe28095efbc9aefbcb3efbca803eefd1d0072b031bb8a59a854adf637cda0d56cfb000000e9809ae5b8b8e5bcbeefbc9ae7828e0000000000e9809ae5b8b8e5bcbeefbc9ae6b0b7000000000000e9809ae5b8b8e5bcbeefbc9ae99bb70000000000e9809ae5b8b8e5bcbeefbc9ae7a59e000000000000e9809ae5b8b8e5bcbeefbc9ae7828ee78886e9809ae5b8b8e5bcbeefbc9ae6b0b7e7888600e9809ae5b8b8e5bcbeefbc9ae99bb7e78886e9809ae5b8b8e5bcbeefbc9ae7a59ee7888600e980a3e5b084e5bcbe0000000000000000e59b9ee5bea9e5bcbeefbc9aefbca1efbcb300000001533093306b3061306f3088308d3057304f304a305898443057307e305930966e995057307e3059304a30855f5f305b3057307e3057305f304a30b2758c30d869673057305f3001ff42308a304c306830463001ffc830e930c330d7302d8a6e7f57307e3057305f3001ffde56a95ff167603057307e30593001ffea30f330af30a830a430c9304a305898443057307e30593001ff5430813093306a305530443001ff040100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'),
    'global': bytes.fromhex('e7a59ee89699e383a6e382a65374756e204772656e616465000000000000000000000000526573746f72652050696c6c4f473a20526573746f72652042616c6c00004f473a20526573746f726520506f73740000536e61726520547261700000000000000000000000000000466f726d616c20546f703a20426c75650000000000000000000000000000466f726d616c20426f74746f6d3a20426c7565000000000000000000000050726f746f747970650000000000000000004b6e69666520500000000000000000547970653530204175746f2d47756e2050000000000000005374616e64617264204275636b6c6572205000000000000000000044756d6d79204465766963650000000000000000004e6f726d616c3a20426c617a652042756c6c65744e6f726d616c3a20467265657a652042756c6c65744e6f726d616c3a20537061726b2042756c6c65744e6f726d616c3a20446976696e652042756c6c65744e6f726d616c3a20426c617a6520426f6d624e6f726d616c3a20467265657a6520426f6d624e6f726d616c3a20537061726b20426f6d624e6f726d616c3a20446976696e6520426f6d62526170696420466972652042756c6c65744865616c696e672053686f743a2041737361756c74990136486f70650a205265637275697404045374756e204772656e616465000000000000000000000000526573746f72652050696c6c4f473a20526573746f72652042616c6c00004f473a20526573746f726520506f73740000536e61726520547261700000000000000000000000000000466f726d616c20546f703a20426c75650000000000000000000000000000466f726d616c20426f74746f6d3a20426c7565000000000000000000000050726f746f747970650000000000000000004b6e69666520500000000000000000547970653530204175746f2d47756e2050000000000000005374616e64617264204275636b6c6572205000000000000000000044756d6d79204465766963650000000000000000004e6f726d616c3a20426c617a652042756c6c65744e6f726d616c3a20467265657a652042756c6c65744e6f726d616c3a20537061726b2042756c6c65744e6f726d616c3a20446976696e652042756c6c65744e6f726d616c3a20426c617a6520426f6d624e6f726d616c3a20467265657a6520426f6d624e6f726d616c3a20537061726b20426f6d624e6f726d616c3a20446976696e6520426f6d62526170696420466972652042756c6c65744865616c696e672053686f743a2041737361756c74990136486f70650a2052656372756974536e697065722042756c6c6574536e697065722042756c6c65743a20426c617a65536e697065722042756c6c65743a20467265657a65536e697065722042756c6c65743a20537061726b536e697065722042756c6c65743a20446976696e65534e2042756c6c65743a20426c617a6520426f6d62534e2042756c6c65743a20467265657a6520426f6d62534e2042756c6c65743a20537061726b20426f6d62534e2042756c6c65743a20446976696e6520426f6d624865616c696e672053686f743a20536e697065724e6f726d616c3a20426c617a652042756c6c65744e6f726d616c3a20467265657a652042756c6c65744e6f726d616c3a20537061726b2042756c6c65744e6f726d616c3a20446976696e652042756c6c65744e6f726d616c3a20426c617a6520426f6d624e6f726d616c3a20467265657a6520426f6d624e6f726d616c3a20537061726b20426f6d624e6f726d616c3a20446976696e6520426f6d62526170696420466972652042756c6c65744865616c696e672053686f743a2041737361756c74486f6d696e672042756c6c65743a20426c617a65486f6d696e672042756c6c65743a20467265657a65486f6d696e672042756c6c65743a20537061726b486f6d696e672042756c6c65743a20446976696e65526f636b6574205368656c6c3a20426c617a650000526f636b6574205368656c6c3a20467265657a6500526f636b6574205368656c6c3a20537061726b0000526f636b6574205368656c6c3a20446976696e65004d6f727461723a20426c617a6500000000004d6f727461723a20467265657a65000000004d6f727461723a20537061726b00000000004d6f727461723a20446976696e65000000004865616c696e672053686f743a20426c6173744275636b73686f743a20426c617a654275636b73686f743a20467265657a654275636b73686f743a20537061726b4275636b73686f743a20446976696e65536c75673a20426c617a6500000000000000000000536c75673a20467265657a65000000000000000000536c75673a20537061726b00000000000000000000536c75673a20446976696e650000000000000000004865616c696e6720456d69747465723a20536869656c6400000000000000046a5bd7fb5b8135d3bab5e389eb8c6fd069e2ecf69901364e6f726d616c3a20426c617a652042756c6c65744e6f726d616c3a20467265657a652042756c6c65744e6f726d616c3a20537061726b2042756c6c65744e6f726d616c3a20446976696e652042756c6c65744e6f726d616c3a20426c617a6520426f6d624e6f726d616c3a20467265657a6520426f6d624e6f726d616c3a20537061726b20426f6d624e6f726d616c3a20446976696e6520426f6d62526170696420466972652042756c6c65744865616c696e672053686f743a2041737361756c7406000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000448656c6c6f2e49276d20636f756e74696e67206f6e20796f752e49276c6c206765742072656164792e536f72727920746f206b65657020796f752e477265617420776f726b215468616e6b73214920736574206120747261702153657474696e67206120526573746f726520506f73742152657175657374696e67204c696e6b2041696421536f72727921'),
}


f32 = np.float32


def mul64(lo, hi, m_lo, m_hi):
    if m_hi == 0 and hi == 0:
        return (lo * m_lo) & MASK64
    a = (hi << 32) | lo
    b = (m_hi << 32) | m_lo
    return (a * b) & MASK64


def lcg_step(state):
    lo = state & MASK32
    hi = (state >> 32) & MASK32
    uVar6 = mul64(lo, hi, 0x01000001, 0)
    u6_lo = uVar6 & MASK32
    u6_hi = (uVar6 >> 32) & MASK32
    part_low = (u6_lo * 0x100) & MASK32
    part_high = (((u6_hi << 8) & MASK32) | (u6_lo >> 0x18)) & MASK32
    concat = (part_high << 32) | part_low
    return ((uVar6 >> 0x10) + concat) & MASK64


def f01_f32(bits32):
    bits = (int(bits32) & 0x7fffff) | 0x3f800000
    val = np.frombuffer(struct.pack('<I', bits), dtype='<f4')[0]
    return f32(val) - f32(1.0)


def gen_table(state):
    fwd = [0] * 256
    inv = [0] * 256
    local = list(range(256))
    remaining = 256
    idx = 0
    for _ in range(256):
        state = lcg_step(state)
        f = f01_f32(state & MASK32)
        product = f32(f) * f32(remaining)
        pick = int(product)
        if pick >= remaining:
            pick = remaining - 1
        if pick < 0:
            pick = 0
        val = local[pick]
        local[pick] = local[remaining - 1]
        fwd[idx] = val
        inv[val] = idx
        idx += 1
        remaining -= 1
    return fwd, inv, state


def init_state(key_lo, key_hi):
    key = (key_hi << 32) | key_lo
    lVar1 = lcg_step(key)
    seed = lcg_step(lVar1)
    f_hi = f01_f32(lVar1 & MASK32)
    f_lo = f01_f32(seed & MASK32)
    part_hi = int(f32(f_hi) * f32(65536.0)) & 0xFFFF
    part_lo = int(f32(f_lo) * f32(65536.0)) & 0xFFFF
    running = ((part_hi << 16) | part_lo) & MASK32
    return running, seed


def derive_key(rtchash: int):
    combined = (UNIVERSAL_CONSTANT + rtchash) & MASK64
    return combined & MASK32, (combined >> 32) & MASK32


def decrypt(ciphertext: bytes, key_lo: int, key_hi: int, length: int = SAVE_SIZE) -> bytes:
    state, seed = init_state(key_lo, key_hi)
    dest = bytearray(length)
    pos = 0
    while pos < length:
        chunk_len = min(256, length - pos)
        fwd, inv, seed = gen_table(seed)
        nwords = (chunk_len - 1 >> 2) + 1
        for w in range(nwords):
            off = pos + w * 4
            src_word = int.from_bytes(ciphertext[off:off + 4], 'little')
            state = (state ^ src_word) & MASK32
            dest[off:off + 4] = state.to_bytes(4, 'little')
        for i in range(chunk_len):
            b = dest[pos + i]
            dest[pos + i] = (inv[b] - i) & 0xFF
        pos += chunk_len
    return bytes(dest)


def encrypt(plaintext: bytes, key_lo: int, key_hi: int, length: int = SAVE_SIZE) -> bytes:
    state, seed = init_state(key_lo, key_hi)
    dest = bytearray(length)
    pos = 0
    while pos < length:
        chunk_len = min(256, length - pos)
        fwd, inv, seed = gen_table(seed)
        nwords = (chunk_len - 1 >> 2) + 1
        step1 = bytearray(nwords * 4)
        for i in range(chunk_len):
            p = plaintext[pos + i]
            step1[i] = fwd[(p + i) & 0xFF]
        for w in range(nwords):
            off = w * 4
            new_state = int.from_bytes(bytes(step1[off:off + 4]), 'little')
            cipher_word = (state ^ new_state) & MASK32
            dest[pos + off:pos + off + 4] = cipher_word.to_bytes(4, 'little')
            state = new_state
        pos += chunk_len
    return bytes(dest)


def compute_checksums(data: bytes):
    assert len(data) == SAVE_SIZE, f'expected {SAVE_SIZE} bytes, got {len(data)}'
    work = bytearray(data)
    for off in (CHKSUM_OFFSET, EZHASH_OFFSET, RTCHASH_OFFSET, RTCHASH_OFFSET + 4,
                TRAILER_OFFSET, TRAILER_OFFSET + 4):
        work[off:off + 4] = b'\x00\x00\x00\x00'
    # (kept as an explicit offset list, not is_key_material(), since that
    # helper is defined further down and checksum zeroing must exactly match
    # the original reverse-engineered field boundaries)
    chksum = 0
    ezhash = 0
    for b in work:
        chksum = (chksum + b) & MASK32
        prod = (ezhash * 0xE0) & MASK32
        ezhash = ((prod ^ b) + (prod >> 8)) & MASK32
    return chksum, ezhash


def patch_checksums(data: bytes) -> bytes:
    chksum, ezhash = compute_checksums(data)
    out = bytearray(data)
    out[CHKSUM_OFFSET:CHKSUM_OFFSET + 4] = chksum.to_bytes(4, 'little')
    out[EZHASH_OFFSET:EZHASH_OFFSET + 4] = ezhash.to_bytes(4, 'little')
    return bytes(out)


def is_key_material(offset: int) -> bool:
    """Per-save random/derived fields - never region-format data, never
    hand-copied between saves. Regenerated (checksums, trailer) or left as
    the source's own value (RtcHash) instead."""
    if CHKSUM_OFFSET <= offset < CHKSUM_OFFSET + 4:
        return True
    if EZHASH_OFFSET <= offset < EZHASH_OFFSET + 4:
        return True
    if RTCHASH_OFFSET <= offset < RTCHASH_OFFSET + 8:
        return True
    if TRAILER_OFFSET <= offset < TRAILER_OFFSET + 8:
        return True
    return False


def build_region_mask(blank_a: bytes, blank_b: bytes):
    """Diff two same-progress (ideally both freshly-initialized) saves from
    different regions. What's left after excluding key material is the set
    of region-format fields: embedded display-cache text (item/equipment/
    bullet catalog names, quick-chat UI strings) that the client apparently
    reads directly rather than re-deriving purely by ID, at least for some
    of these fields - confirmed by the region-swap tests."""
    assert len(blank_a) == len(blank_b) == SAVE_SIZE
    diffs = (i for i in range(SAVE_SIZE) if blank_a[i] != blank_b[i])
    return [i for i in diffs if not is_key_material(i)]


def cmd_decrypt(args):
    with open(args.input, 'rb') as f:
        ciphertext = f.read()
    if len(ciphertext) != SAVE_SIZE:
        print(f'WARNING: input is {len(ciphertext)} bytes, expected {SAVE_SIZE}. Continuing anyway.')

    if args.rtchash:
        # manual override, in case the trailer is missing/corrupted
        rtchash = int(args.rtchash, 16)
        source = 'manual override'
    else:
        # self-derived: the key seed is an unencrypted copy of RtcHash sitting
        # in the file's own last 8 bytes - no debugger/live capture needed.
        trailer = ciphertext[-8:]
        rtchash = int.from_bytes(trailer, 'little')
        source = f'read from file trailer ({trailer.hex()})'

    key_lo, key_hi = derive_key(rtchash)
    body_len = len(ciphertext) - 8
    body = decrypt(ciphertext[:body_len], key_lo, key_hi, body_len)
    plaintext = body + ciphertext[-8:]  # keep trailer for compatibility with checksum/info tooling

    with open(args.output, 'wb') as f:
        f.write(plaintext)

    print(f'Decrypted {len(plaintext)} bytes -> {args.output}')
    print(f'  RtcHash: {source}')
    print(f'  key: lo={key_lo:#010x} hi={key_hi:#010x}')

    if plaintext[:6] == b'553118':
        print('  Header check: OK ("553118" magic found)')
    else:
        print('  Header check: FAILED - the derived RtcHash is probably wrong,')
        print('  or the input was not a valid SaveData ciphertext.')

    if len(plaintext) == SAVE_SIZE:
        stored_chk = int.from_bytes(plaintext[CHKSUM_OFFSET:CHKSUM_OFFSET + 4], 'little')
        stored_ez = int.from_bytes(plaintext[EZHASH_OFFSET:EZHASH_OFFSET + 4], 'little')
        calc_chk, calc_ez = compute_checksums(plaintext)
        ok = (stored_chk == calc_chk) and (stored_ez == calc_ez)
        print(f'  Checksum check: {"OK" if ok else "MISMATCH"}')


def cmd_encrypt(args):
    with open(args.input, 'rb') as f:
        plaintext = f.read()
    if len(plaintext) != SAVE_SIZE:
        print(f'ERROR: plaintext must be exactly {SAVE_SIZE} bytes (got {len(plaintext)})')
        sys.exit(1)

    if args.fix_checksums:
        plaintext = patch_checksums(plaintext)
        print('Recomputed and patched ChkSum/EzHash before encrypting.')

    rtchash_bytes = plaintext[RTCHASH_OFFSET:RTCHASH_OFFSET + 8]
    rtchash = int.from_bytes(rtchash_bytes, 'little')
    key_lo, key_hi = derive_key(rtchash)
    body = encrypt(plaintext[:BODY_SIZE], key_lo, key_hi, BODY_SIZE)
    ciphertext = body + rtchash_bytes  # trailer is an unencrypted copy of RtcHash

    with open(args.output, 'wb') as f:
        f.write(ciphertext)

    print(f'Encrypted {len(ciphertext)} bytes -> {args.output}')
    print(f'  RtcHash used: {rtchash:#018x}')
    print(f'  key: lo={key_lo:#010x} hi={key_hi:#010x}')


def _load_as_plaintext(path):
    """Accept either a plaintext SaveData file or a raw SECURE.BIN - decrypt
    automatically (self-derived key) if it looks like ciphertext."""
    with open(path, 'rb') as f:
        raw = f.read()
    if len(raw) != SAVE_SIZE:
        print(f'WARNING: {path} is {len(raw)} bytes, expected {SAVE_SIZE}. Continuing anyway.')
    if raw[:6] == b'553118':
        return bytearray(raw)
    trailer = raw[-8:]
    rtchash = int.from_bytes(trailer, 'little')
    key_lo, key_hi = derive_key(rtchash)
    body_len = len(raw) - 8
    body = decrypt(raw[:body_len], key_lo, key_hi, body_len)
    return bytearray(body + trailer)


def _expand_ranges(ranges):
    offsets = []
    for start, end in ranges:
        offsets.extend(range(start, end + 1))
    return offsets


def cmd_port_region(args):
    plaintext = _load_as_plaintext(args.input)

    using_custom = args.source_blank or args.target_blank
    if using_custom:
        if not (args.source_blank and args.target_blank):
            print('ERROR: --source-blank and --target-blank must be used together.')
            sys.exit(1)
        with open(args.source_blank, 'rb') as f:
            blank_src = f.read()
        with open(args.target_blank, 'rb') as f:
            blank_tgt = f.read()
        mask = build_region_mask(blank_src, blank_tgt)
        for i in mask:
            plaintext[i] = blank_tgt[i]
        region_note = f'custom blank-save diff ({len(mask)} bytes)'
    else:
        if not args.to:
            print('ERROR: specify either --to {jp,global} (baked-in Vita data) '
                  'or both --source-blank and --target-blank (custom).')
            sys.exit(1)
        mask = _expand_ranges(VITA_REGION_RANGES)
        target_bytes = VITA_REGION_DATA[args.to]
        for offset, val in zip(mask, target_bytes):
            plaintext[offset] = val
        region_note = f'baked-in Vita region data -> {args.to} ({len(mask)} bytes)'

    patched = patch_checksums(bytes(plaintext))

    if args.plaintext_out:
        out = patched
        note = 'plaintext'
    else:
        rtchash_bytes = patched[RTCHASH_OFFSET:RTCHASH_OFFSET + 8]
        rtchash = int.from_bytes(rtchash_bytes, 'little')
        key_lo, key_hi = derive_key(rtchash)
        body = encrypt(patched[:BODY_SIZE], key_lo, key_hi, BODY_SIZE)
        out = body + rtchash_bytes
        note = 'SECURE.BIN (encrypted)'

    with open(args.output, 'wb') as f:
        f.write(out)

    print(f'Ported using {region_note} -> {args.output} ({note})')
    print('  All other bytes (character stats, inventory, quest progress, etc.) left untouched.')
    print('  NOTE: this swaps the fields known to matter so far (item/equipment/bullet')
    print('  catalog-name cache + quick-chat UI text block). If something in the target')
    print('  region still looks or behaves wrong, there may be an additional field this')
    print('  mask does not yet cover - compare two more same-state blanks to check.')


def cmd_checksums(args):
    with open(args.input, 'rb') as f:
        data = f.read()
    if len(data) != SAVE_SIZE:
        print(f'ERROR: expected {SAVE_SIZE} bytes, got {len(data)}')
        sys.exit(1)

    stored_chk = int.from_bytes(data[CHKSUM_OFFSET:CHKSUM_OFFSET + 4], 'little')
    stored_ez = int.from_bytes(data[EZHASH_OFFSET:EZHASH_OFFSET + 4], 'little')
    calc_chk, calc_ez = compute_checksums(data)

    print(f'Stored   ChkSum={stored_chk:#010x}  EzHash={stored_ez:#010x}')
    print(f'Computed ChkSum={calc_chk:#010x}  EzHash={calc_ez:#010x}')
    print('MATCH' if (stored_chk == calc_chk and stored_ez == calc_ez) else 'MISMATCH')

    if args.fix:
        fixed = patch_checksums(data)
        with open(args.fix, 'wb') as f:
            f.write(fixed)
        print(f'Wrote corrected file -> {args.fix}')


def cmd_info(args):
    with open(args.input, 'rb') as f:
        data = f.read()
    if len(data) != SAVE_SIZE:
        print(f'WARNING: expected {SAVE_SIZE} bytes, got {len(data)}')

    print(f'File size: {len(data)} bytes')
    print(f'Header (offset 0x0): {data[:8]!r}')
    print(f'ChkSum (0x10):    {int.from_bytes(data[0x10:0x14], "little"):#010x}')
    print(f'EzHash (0x14):    {int.from_bytes(data[0x14:0x18], "little"):#010x}')
    print(f'Visual.Lang (0x20):    {data[0x20]}')
    print(f'Visual.Country (0x21): {data[0x21]}')
    rtchash_bytes = data[RTCHASH_OFFSET:RTCHASH_OFFSET + 8]
    rtchash = int.from_bytes(rtchash_bytes, 'little')
    key_lo, key_hi = derive_key(rtchash)
    print(f'RtcHash  (0x40):  {rtchash_bytes.hex()}  <- key seed')
    print(f'  -> derived key: lo={key_lo:#010x} hi={key_hi:#010x}')
    if len(data) >= TRAILER_OFFSET + 8:
        trailer = data[TRAILER_OFFSET:TRAILER_OFFSET + 8]
        note = '(unencrypted copy of RtcHash, not a separate field)'
        print(f'Trailer (0xdb048): {trailer.hex()}  {note}')
        if trailer != rtchash_bytes:
            print('  NOTE: trailer != RtcHash - this plaintext capture is stale/live-memory,')
            print('  not the on-disk form. Re-derive the key from RtcHash, not this trailer,')
            print('  when re-encrypting.')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)

    p_dec = sub.add_parser('decrypt', help='Decrypt a SECURE.BIN into plaintext')
    p_dec.add_argument('input')
    p_dec.add_argument('output')
    p_dec.add_argument('--rtchash', required=False,
                        help='Override RtcHash as 16 hex digits. Normally not needed - '
                             'the key is read automatically from the file\'s own last 8 bytes.')
    p_dec.set_defaults(func=cmd_decrypt)

    p_enc = sub.add_parser('encrypt', help='Encrypt plaintext into a SECURE.BIN')
    p_enc.add_argument('input')
    p_enc.add_argument('output')
    p_enc.add_argument('--fix-checksums', action='store_true',
                        help='Recompute ChkSum/EzHash before encrypting (use after editing plaintext fields)')
    p_enc.set_defaults(func=cmd_encrypt)

    p_chk = sub.add_parser('checksums', help='Check / fix ChkSum and EzHash on a plaintext file')
    p_chk.add_argument('input')
    p_chk.add_argument('--fix', metavar='OUTPUT', help='Write a corrected copy to OUTPUT')
    p_chk.set_defaults(func=cmd_checksums)

    p_info = sub.add_parser('info', help='Show known fields of a plaintext SaveData file')
    p_info.add_argument('input')
    p_info.set_defaults(func=cmd_info)

    p_region = sub.add_parser('port-region',
                               help='Swap region-format fields (item/equipment/bullet catalog-name '
                                    'cache + quick-chat UI text) between two regions, e.g. Global<->JP. '
                                    'Everything else (stats, inventory, quest progress, etc.) is left '
                                    'untouched. Input can be a plaintext save or a raw SECURE.BIN.')
    p_region.add_argument('input')
    p_region.add_argument('output')
    p_region.add_argument('--to', choices=sorted(VITA_REGION_DATA.keys()),
                           help='Target region, using baked-in Vita region data. No blank-save files '
                                'needed - this is the normal way to use port-region for Vita JP<->Global.')
    p_region.add_argument('--source-blank', required=False,
                           help='Advanced/other platforms: freshly-initialized plaintext save from the '
                                'SAME region as --input. Must be paired with --target-blank. Overrides --to.')
    p_region.add_argument('--target-blank', required=False,
                           help='Advanced/other platforms: freshly-initialized plaintext save from the '
                                'region to port TO. Must be paired with --source-blank. Overrides --to.')
    p_region.add_argument('--plaintext-out', action='store_true',
                           help='Write plaintext instead of re-encrypting to a SECURE.BIN')
    p_region.set_defaults(func=cmd_port_region)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
