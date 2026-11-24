"""Chạy DES và AES-128 trên toàn bộ test vector, ghi giá trị từng trạng thái vào output/.

    python main.py        # ghi file output/*.txt, in bảng tổng hợp
    python main.py -v     # in thêm toàn bộ trạng thái ra màn hình
"""

import os
import sys

from common import parse_hex, to_hex
from des import des_encrypt, des_decrypt
from aes import aes_encrypt, aes_decrypt
from test_vectors import DES_VECTORS, AES_VECTORS

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")


def run_vector(algo, name, desc, key_hex, plain_hex, expected_hex, n_bits, encrypt, decrypt, verbose):
    lines = []
    log = lines.append

    key = parse_hex(key_hex, n_bits, "Khóa")
    plain = parse_hex(plain_hex, n_bits, "Bản rõ")
    expected = parse_hex(expected_hex, n_bits, "Bản mã mong đợi")

    log(f"# {algo} - {desc}")
    log("")
    cipher = encrypt(plain, key, log)
    log("")
    recovered = decrypt(cipher, key, log)

    ok_cipher = cipher == expected
    ok_plain = recovered == plain
    log("")
    log("KIỂM ĐỊNH")
    log(f"  Bản mã tính được : {to_hex(cipher, n_bits)}")
    log(f"  Bản mã mong đợi  : {to_hex(expected, n_bits)}   -> {'ĐÚNG' if ok_cipher else 'SAI'}")
    log(f"  Giải mã lại      : {to_hex(recovered, n_bits)}   -> {'ĐÚNG' if ok_plain else 'SAI'}")

    path = os.path.join(OUTPUT_DIR, f"{algo.split('-')[0].lower()}_{name}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    if verbose:
        print("\n".join(lines))
        print()

    return [algo, name, to_hex(key, n_bits), to_hex(plain, n_bits), to_hex(cipher, n_bits),
            "ĐÚNG" if (ok_cipher and ok_plain) else "SAI", os.path.basename(path)]


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    verbose = "-v" in sys.argv
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    rows = []
    for name, desc, k, p, c in DES_VECTORS:
        rows.append(run_vector("DES", name, desc, k, p, c, 64, des_encrypt, des_decrypt, verbose))
    for name, desc, k, p, c in AES_VECTORS:
        rows.append(run_vector("AES-128", name, desc, k, p, c, 128, aes_encrypt, aes_decrypt, verbose))

    header = ["Thuật toán", "Vector", "Khóa", "Bản rõ", "Bản mã", "Kết quả", "File"]
    widths = [max(len(str(r[i])) for r in rows + [header]) for i in range(len(header))]
    table = [" | ".join(str(v).ljust(w) for v, w in zip(row, widths)).rstrip() for row in [header] + rows]
    table.insert(1, "-+-".join("-" * w for w in widths))

    summary = "\n".join(table)
    with open(os.path.join(OUTPUT_DIR, "TONG_HOP.txt"), "w", encoding="utf-8") as f:
        f.write(summary + "\n")
    print(summary)

    if any(r[5] != "ĐÚNG" for r in rows):
        sys.exit(1)


if __name__ == "__main__":
    main()
