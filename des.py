"""DES (Data Encryption Standard, FIPS 46-3) - cài đặt theo từng bước, in giá trị mọi trạng thái.

Quy ước: khối 64 bit, khóa 64 bit được biểu diễn bằng số nguyên Python.
Các bảng hoán vị đánh số bit từ 1 (bit trái nhất = MSB) giống như trong giáo trình.

Chạy:  python des.py -k 133457799BBCDFF1 -p 0123456789ABCDEF
       python des.py -k 133457799BBCDFF1 -c 85E813540F0AB405 (giải mã)
"""

from common import parse_hex, to_hex, to_bin, no_log

# ---------------------------------------------------------------------------
# 1. CÁC BẢNG CỦA DES
# ---------------------------------------------------------------------------

# Hoán vị khởi đầu IP: bit thứ i của đầu ra = bit IP[i] của đầu vào
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Hoán vị kết thúc IP^-1 (nghịch đảo của IP)
IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

# Hoán vị mở rộng E: 32 bit -> 48 bit
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# Hoán vị P sau 8 hộp S: 32 bit -> 32 bit
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# Lựa chọn hoán vị PC-1: 64 bit khóa -> 56 bit (bỏ 8 bit chẵn lẻ 8,16,...,64)
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

# Lựa chọn hoán vị PC-2: 56 bit (C||D) -> 48 bit khóa con
PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# Số bit dịch vòng trái của C, D ở mỗi vòng (tổng = 28)
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# 8 hộp S, mỗi hộp 4 hàng x 16 cột
S_BOX = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]


# ---------------------------------------------------------------------------
# 2. CÁC PHÉP TOÁN CƠ BẢN
# ---------------------------------------------------------------------------

def permute(block, table, n_in):
    """Hoán vị / chọn bit theo bảng.

    block : số nguyên n_in bit.
    table : danh sách vị trí bit (đánh số 1..n_in, tính từ bit trái nhất).
    Bit thứ i của kết quả = bit thứ table[i] của đầu vào.
    """
    out = 0
    for pos in table:
        bit = (block >> (n_in - pos)) & 1   # lấy bit ở vị trí `pos` tính từ trái
        out = (out << 1) | bit              # nối bit đó vào bên phải kết quả
    return out


def stallings_format(k48):
    """Khóa con 48 bit -> 8 nhóm 6 bit, mỗi nhóm in 2 chữ số hex (cách in trong Stallings, Bảng 3.5)."""
    return "".join(f"{(k48 >> (42 - 6 * i)) & 0x3F:02X}" for i in range(8))


def rotate_left_28(x, n):
    """Dịch vòng trái số 28 bit đi n bit."""
    return ((x << n) | (x >> (28 - n))) & 0xFFFFFFF


# ---------------------------------------------------------------------------
# 3. SINH KHÓA CON
# ---------------------------------------------------------------------------

def generate_subkeys(key, log=no_log):
    """Sinh 16 khóa con 48 bit K1..K16 từ khóa 64 bit."""
    log("BƯỚC 1. SINH 16 KHÓA CON")
    log(f"  K         = {to_hex(key, 64)}")
    log(f"            = {to_bin(key, 64, 8)}")

    k56 = permute(key, PC1, 64)
    log(f"  PC-1(K)   = {to_bin(k56, 56, 7)}  (56 bit)")

    c = k56 >> 28            # 28 bit trái
    d = k56 & 0xFFFFFFF      # 28 bit phải
    log(f"  C0 = {to_bin(c, 28, 7)}  ({to_hex(c, 28)})")
    log(f"  D0 = {to_bin(d, 28, 7)}  ({to_hex(d, 28)})")

    subkeys = []
    for i in range(16):
        c = rotate_left_28(c, SHIFTS[i])
        d = rotate_left_28(d, SHIFTS[i])
        k = permute((c << 28) | d, PC2, 56)
        subkeys.append(k)
        log(f"  Vòng {i + 1:2d}: dịch vòng trái {SHIFTS[i]} bit, K{i + 1} = PC-2(C{i + 1} || D{i + 1})")
        log(f"     C{i + 1:<2d} = {to_bin(c, 28, 7)}  ({to_hex(c, 28)})")
        log(f"     D{i + 1:<2d} = {to_bin(d, 28, 7)}  ({to_hex(d, 28)})")
        log(f"     K{i + 1:<2d} = {to_bin(k, 48, 6)}  = {to_hex(k, 48)}"
            f"  (dạng Stallings: {stallings_format(k)})")
    return subkeys


# ---------------------------------------------------------------------------
# 4. HÀM f VÀ 16 VÒNG FEISTEL
# ---------------------------------------------------------------------------

def feistel_f(r, subkey, key_name, log=no_log):
    """Hàm f(R, K) = P( S( E(R) XOR K ) )."""
    pad = "      "
    e = permute(r, E, 32)
    log(f"{pad}E(R)          = {to_bin(e, 48, 6)}  = {to_hex(e, 48)}")
    log(f"{pad}{key_name:<14}= {to_bin(subkey, 48, 6)}  = {to_hex(subkey, 48)}")

    x = e ^ subkey
    log(f"{pad}E(R) XOR {key_name:<5}= {to_bin(x, 48, 6)}  = {to_hex(x, 48)}")

    # Chia 48 bit thành 8 nhóm 6 bit, nhóm thứ i đi qua hộp S_i
    s_out = 0
    details = []
    for i in range(8):
        six = (x >> (42 - 6 * i)) & 0x3F          # nhóm 6 bit thứ i (tính từ trái)
        row = ((six >> 5) & 1) * 2 + (six & 1)     # hàng = bit đầu + bit cuối
        col = (six >> 1) & 0xF                     # cột  = 4 bit giữa
        val = S_BOX[i][row][col]
        s_out = (s_out << 4) | val
        details.append(f"S{i + 1}: {six:06b} (h{row},c{col:2d}) -> {val:04b}")
    log(f"{pad}  " + " | ".join(details[:4]))
    log(f"{pad}  " + " | ".join(details[4:]))
    log(f"{pad}Đầu ra hộp S  = {to_bin(s_out, 32, 4)}  = {to_hex(s_out, 32)}")

    f = permute(s_out, P, 32)
    log(f"{pad}f = P(S)      = {to_bin(f, 32, 4)}  = {to_hex(f, 32)}")
    return f


def des_rounds(block, subkeys, key_names, log=no_log):
    """IP -> 16 vòng Feistel -> hoán đổi L,R -> IP^-1. Dùng chung cho mã hóa và giải mã."""
    log("BƯỚC 2. HOÁN VỊ KHỞI ĐẦU IP")
    log(f"  Đầu vào   = {to_hex(block, 64)} = {to_bin(block, 64, 8)}")
    ip = permute(block, IP, 64)
    log(f"  IP        = {to_hex(ip, 64)} = {to_bin(ip, 64, 8)}")

    left = ip >> 32
    right = ip & 0xFFFFFFFF
    log(f"  L0 = {to_hex(left, 32)}   R0 = {to_hex(right, 32)}")

    log("BƯỚC 3. 16 VÒNG FEISTEL:  L_i = R_(i-1),  R_i = L_(i-1) XOR f(R_(i-1), K)")
    for i in range(16):
        log(f"  --- Vòng {i + 1} (dùng {key_names[i]}) ---")
        f = feistel_f(right, subkeys[i], key_names[i], log)
        left, right = right, left ^ f
        log(f"      L{i + 1:<2d} = {to_hex(left, 32)}   R{i + 1:<2d} = {to_hex(right, 32)}")

    log("BƯỚC 4. HOÁN ĐỔI CUỐI VÀ HOÁN VỊ IP^-1")
    pre_output = (right << 32) | left       # sau vòng 16 đổi chỗ: R16 || L16
    log(f"  R16 L16   = {to_hex(pre_output, 64)} = {to_bin(pre_output, 64, 8)}")
    out = permute(pre_output, IP_INV, 64)
    log(f"  IP^-1     = {to_hex(out, 64)} = {to_bin(out, 64, 8)}")
    return out


# ---------------------------------------------------------------------------
# 5. MÃ HÓA / GIẢI MÃ
# ---------------------------------------------------------------------------

def des_encrypt(plain, key, log=no_log):
    log("=" * 78)
    log(f"DES - MÃ HÓA    P = {to_hex(plain, 64)}    K = {to_hex(key, 64)}")
    log("=" * 78)
    subkeys = generate_subkeys(key, log)
    names = [f"K{i + 1}" for i in range(16)]
    cipher = des_rounds(plain, subkeys, names, log)
    log(f"==> BẢN MÃ C = {to_hex(cipher, 64)}")
    return cipher


def des_decrypt(cipher, key, log=no_log):
    """Giải mã = cùng cấu trúc với mã hóa, nhưng dùng khóa con ngược thứ tự K16..K1."""
    log("=" * 78)
    log(f"DES - GIẢI MÃ   C = {to_hex(cipher, 64)}    K = {to_hex(key, 64)}")
    log("=" * 78)
    subkeys = generate_subkeys(key, log)
    names = [f"K{16 - i}" for i in range(16)]
    plain = des_rounds(cipher, subkeys[::-1], names, log)
    log(f"==> BẢN RÕ P = {to_hex(plain, 64)}")
    return plain


if __name__ == "__main__":
    import argparse
    import sys

    sys.stdout.reconfigure(encoding="utf-8")  # để in được tiếng Việt trên Windows
    ap = argparse.ArgumentParser(description="DES - in giá trị từng trạng thái")
    ap.add_argument("-k", "--key", required=True, help="khóa 64 bit (16 chữ số hex)")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--plain", help="bản rõ 64 bit -> mã hóa")
    group.add_argument("-c", "--cipher", help="bản mã 64 bit -> giải mã")
    args = ap.parse_args()

    k = parse_hex(args.key, 64, "Khóa")
    if args.plain is not None:
        des_encrypt(parse_hex(args.plain, 64, "Bản rõ"), k, log=print)
    else:
        des_decrypt(parse_hex(args.cipher, 64, "Bản mã"), k, log=print)
