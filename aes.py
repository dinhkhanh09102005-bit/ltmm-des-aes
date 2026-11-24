"""AES-128 (FIPS-197) - cài đặt theo từng bước, in giá trị mọi trạng thái.

Trạng thái (state) là ma trận 4x4 byte: state[hàng][cột].
16 byte của khối vào được xếp THEO CỘT: state[r][c] = in[r + 4c]
(byte 0..3 vào cột 0, byte 4..7 vào cột 1, ...), giống FIPS-197.

Chạy:  python aes.py -k 2B7E151628AED2A6ABF7158809CF4F3C -p 3243F6A8885A308D313198A2E0370734
       python aes.py -k 2B7E151628AED2A6ABF7158809CF4F3C -c 3925841D02DC09FBDC118597196A0B32 (giải mã)
"""

from common import parse_hex, to_hex, no_log

# ---------------------------------------------------------------------------
# 1. CÁC BẢNG CỦA AES
# ---------------------------------------------------------------------------

# Hộp S: SBOX[x] với x = 0x00..0xFF (hàng = nửa byte cao, cột = nửa byte thấp)
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

# Hộp S ngược: nếu SBOX[x] = y thì INV_SBOX[y] = x
INV_SBOX = [0] * 256
for _x in range(256):
    INV_SBOX[SBOX[_x]] = _x

# Hằng số vòng Rcon[i] = x^(i-1) trong GF(2^8), i = 1..10
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

NR = 10  # AES-128: 10 vòng


# ---------------------------------------------------------------------------
# 2. CHUYỂN ĐỔI KHỐI <-> TRẠNG THÁI, IN TRẠNG THÁI
# ---------------------------------------------------------------------------

def int_to_state(value):
    """Số nguyên 128 bit -> ma trận 4x4, xếp byte theo cột."""
    b = value.to_bytes(16, "big")
    return [[b[r + 4 * c] for c in range(4)] for r in range(4)]


def state_to_int(state):
    """Ma trận 4x4 -> số nguyên 128 bit (đọc theo cột)."""
    b = bytes(state[r][c] for c in range(4) for r in range(4))
    return int.from_bytes(b, "big")


def state_hex(state):
    return to_hex(state_to_int(state), 128)


def log_steps(log, steps):
    """In nhiều trạng thái cạnh nhau dạng ma trận 4x4, sau đó in dạng chuỗi hex.

    steps: danh sách (tên, trạng thái).
    """
    width = 15
    log(("    " + "".join(name.ljust(width) for name, _ in steps)).rstrip())
    for r in range(4):
        row_text = ""
        for _, s in steps:
            row_text += " ".join(f"{s[r][c]:02X}" for c in range(4)).ljust(width)
        log(("    " + row_text).rstrip())
    for name, s in steps:
        log(f"    {name:<14}: {state_hex(s)}")


# ---------------------------------------------------------------------------
# 3. PHÉP TOÁN TRÊN GF(2^8), đa thức tối giản m(x) = x^8 + x^4 + x^3 + x + 1 (0x11B)
# ---------------------------------------------------------------------------

def xtime(a):
    """Nhân a với x (tức 0x02) trong GF(2^8)."""
    a = a << 1
    if a & 0x100:          # tràn bậc 8 -> rút gọn theo m(x)
        a ^= 0x11B
    return a


def gmul(a, b):
    """Nhân hai byte a*b trong GF(2^8) bằng phương pháp nhân - cộng (XOR) dần."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


# ---------------------------------------------------------------------------
# 4. BỐN PHÉP BIẾN ĐỔI CỦA VÒNG VÀ PHÉP NGƯỢC
# ---------------------------------------------------------------------------

def sub_bytes(s):
    """Thay mỗi byte bằng SBOX[byte]."""
    return [[SBOX[s[r][c]] for c in range(4)] for r in range(4)]


def inv_sub_bytes(s):
    return [[INV_SBOX[s[r][c]] for c in range(4)] for r in range(4)]


def shift_rows(s):
    """Hàng r dịch vòng trái r byte (hàng 0 giữ nguyên)."""
    return [s[r][r:] + s[r][:r] for r in range(4)]


def inv_shift_rows(s):
    """Hàng r dịch vòng phải r byte."""
    return [s[r][4 - r:] + s[r][:4 - r] for r in range(4)]


def mix_columns(s):
    """Nhân mỗi cột với ma trận cố định [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]] trong GF(2^8)."""
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        a0, a1, a2, a3 = s[0][c], s[1][c], s[2][c], s[3][c]
        out[0][c] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3
        out[1][c] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3
        out[2][c] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3)
        out[3][c] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2)
    return out


def inv_mix_columns(s):
    """Ma trận ngược [[0E,0B,0D,09],[09,0E,0B,0D],[0D,09,0E,0B],[0B,0D,09,0E]]."""
    out = [[0] * 4 for _ in range(4)]
    for c in range(4):
        a0, a1, a2, a3 = s[0][c], s[1][c], s[2][c], s[3][c]
        out[0][c] = gmul(a0, 0x0E) ^ gmul(a1, 0x0B) ^ gmul(a2, 0x0D) ^ gmul(a3, 0x09)
        out[1][c] = gmul(a0, 0x09) ^ gmul(a1, 0x0E) ^ gmul(a2, 0x0B) ^ gmul(a3, 0x0D)
        out[2][c] = gmul(a0, 0x0D) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0E) ^ gmul(a3, 0x0B)
        out[3][c] = gmul(a0, 0x0B) ^ gmul(a1, 0x0D) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0E)
    return out


def add_round_key(s, k):
    """XOR từng byte của trạng thái với khóa vòng."""
    return [[s[r][c] ^ k[r][c] for c in range(4)] for r in range(4)]


# ---------------------------------------------------------------------------
# 5. MỞ RỘNG KHÓA (KeyExpansion): 16 byte khóa -> 44 từ w0..w43 -> 11 khóa vòng
# ---------------------------------------------------------------------------

def word_hex(w):
    return "".join(f"{b:02X}" for b in w)


def xor_words(a, b):
    return [x ^ y for x, y in zip(a, b)]


def key_expansion(key, log=no_log):
    log("BƯỚC 1. MỞ RỘNG KHÓA (KeyExpansion)")
    kb = key.to_bytes(16, "big")
    w = [list(kb[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4):
        log(f"  w{i:<2d} = {word_hex(w[i])}   (lấy trực tiếp từ khóa)")

    for i in range(4, 4 * (NR + 1)):
        temp = w[i - 1]
        if i % 4 == 0:
            rot = temp[1:] + temp[:1]                     # RotWord: dịch vòng trái 1 byte
            sub = [SBOX[b] for b in rot]                  # SubWord: thay từng byte qua S-box
            rcon = [RCON[i // 4 - 1], 0, 0, 0]
            temp = xor_words(sub, rcon)
            w.append(xor_words(w[i - 4], temp))
            log(f"  w{i:<2d}: RotWord(w{i - 1}) = {word_hex(rot)}, SubWord = {word_hex(sub)}, "
                f"XOR Rcon[{i // 4}]={word_hex(rcon)} -> {word_hex(temp)}")
            log(f"        w{i} = w{i - 4} XOR {word_hex(temp)} = {word_hex(w[i])}")
        else:
            w.append(xor_words(w[i - 4], temp))
            log(f"  w{i:<2d} = w{i - 4} XOR w{i - 1} = {word_hex(w[i])}")

    # Khóa vòng thứ r gồm 4 từ w[4r..4r+3], mỗi từ là 1 cột của ma trận
    round_keys = []
    for rnd in range(NR + 1):
        k = [[w[4 * rnd + c][r] for c in range(4)] for r in range(4)]
        round_keys.append(k)
    log("  Các khóa vòng:")
    for rnd in range(NR + 1):
        log(f"    K{rnd:<2d} = {state_hex(round_keys[rnd])}   (w{4 * rnd}..w{4 * rnd + 3})")
    return round_keys


# ---------------------------------------------------------------------------
# 6. MÃ HÓA / GIẢI MÃ
# ---------------------------------------------------------------------------

def aes_encrypt(plain, key, log=no_log):
    log("=" * 92)
    log(f"AES-128 - MÃ HÓA    P = {to_hex(plain, 128)}    K = {to_hex(key, 128)}")
    log("=" * 92)
    rk = key_expansion(key, log)

    log("BƯỚC 2. VÒNG 0: AddRoundKey(P, K0)")
    p = int_to_state(plain)
    s = add_round_key(p, rk[0])
    log_steps(log, [("Bản rõ", p), ("K0", rk[0]), ("Đầu ra vòng 0", s)])

    log("BƯỚC 3. VÒNG 1..10: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey (vòng 10 bỏ MixColumns)")
    for rnd in range(1, NR + 1):
        log(f"  --- Vòng {rnd} ---")
        start = s
        s1 = sub_bytes(start)
        s2 = shift_rows(s1)
        steps = [("Đầu vòng", start), ("SubBytes", s1), ("ShiftRows", s2)]
        if rnd < NR:
            s3 = mix_columns(s2)
            steps.append(("MixColumns", s3))
        else:
            s3 = s2                      # vòng cuối không có MixColumns
        s = add_round_key(s3, rk[rnd])
        steps += [(f"K{rnd}", rk[rnd]), (f"Đầu ra vòng {rnd}", s)]
        log_steps(log, steps)

    cipher = state_to_int(s)
    log(f"==> BẢN MÃ C = {to_hex(cipher, 128)}")
    return cipher


def aes_decrypt(cipher, key, log=no_log):
    """Giải mã ngược (Inverse Cipher, FIPS-197 mục 5.3): dùng khóa vòng K10 -> K0."""
    log("=" * 92)
    log(f"AES-128 - GIẢI MÃ   C = {to_hex(cipher, 128)}    K = {to_hex(key, 128)}")
    log("=" * 92)
    rk = key_expansion(key, log)

    log("BƯỚC 2. VÒNG 0: AddRoundKey(C, K10)")
    c = int_to_state(cipher)
    s = add_round_key(c, rk[NR])
    log_steps(log, [("Bản mã", c), (f"K{NR}", rk[NR]), ("Đầu ra vòng 0", s)])

    log("BƯỚC 3. VÒNG 1..10: InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns (vòng 10 bỏ InvMixColumns)")
    for rnd in range(1, NR + 1):
        key_index = NR - rnd
        log(f"  --- Vòng {rnd} (dùng K{key_index}) ---")
        start = s
        s1 = inv_shift_rows(start)
        s2 = inv_sub_bytes(s1)
        s3 = add_round_key(s2, rk[key_index])
        steps = [("Đầu vòng", start), ("InvShiftRows", s1), ("InvSubBytes", s2),
                 (f"K{key_index}", rk[key_index]), ("AddRoundKey", s3)]
        if rnd < NR:
            s = inv_mix_columns(s3)
            steps.append(("InvMixColumns", s))
        else:
            s = s3
        log_steps(log, steps)

    plain = state_to_int(s)
    log(f"==> BẢN RÕ P = {to_hex(plain, 128)}")
    return plain


if __name__ == "__main__":
    import argparse
    import sys

    sys.stdout.reconfigure(encoding="utf-8")  # để in được tiếng Việt trên Windows
    ap = argparse.ArgumentParser(description="AES-128 - in giá trị từng trạng thái")
    ap.add_argument("-k", "--key", required=True, help="khóa 128 bit (32 chữ số hex)")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--plain", help="bản rõ 128 bit -> mã hóa")
    group.add_argument("-c", "--cipher", help="bản mã 128 bit -> giải mã")
    args = ap.parse_args()

    k = parse_hex(args.key, 128, "Khóa")
    if args.plain is not None:
        aes_encrypt(parse_hex(args.plain, 128, "Bản rõ"), k, log=print)
    else:
        aes_decrypt(parse_hex(args.cipher, 128, "Bản mã"), k, log=print)
