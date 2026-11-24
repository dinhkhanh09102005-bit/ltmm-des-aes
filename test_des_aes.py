"""Kiểm thử tự động:  python -m unittest -v test_des_aes

1. Test vector đã biết đáp án (của lớp, Stallings, Grabbe, FIPS-197).
2. Giải mã(Mã hóa(P)) = P.
3. Tính chất: IP^-1 là nghịch đảo của IP; bảng S-box AES đúng định nghĩa toán học.
4. So sánh chéo 200 cặp (khóa, bản rõ) ngẫu nhiên với thư viện pycryptodome
   (tự bỏ qua nếu chưa cài:  pip install pycryptodome).
"""

import random
import unittest

from des import des_encrypt, des_decrypt, permute, IP, IP_INV, S_BOX
from aes import aes_encrypt, aes_decrypt, SBOX, gmul
from test_vectors import DES_VECTORS, AES_VECTORS

try:
    from Crypto.Cipher import DES as RefDES, AES as RefAES
    HAVE_REF = True
except ImportError:
    HAVE_REF = False

N_RANDOM = 200


class TestDES(unittest.TestCase):
    def test_known_vectors(self):
        for name, _, k, p, c in DES_VECTORS:
            with self.subTest(vector=name):
                key, plain, cipher = int(k, 16), int(p, 16), int(c, 16)
                self.assertEqual(des_encrypt(plain, key), cipher)
                self.assertEqual(des_decrypt(cipher, key), plain)

    def test_ip_inverse(self):
        rnd = random.Random(1)
        for _ in range(100):
            x = rnd.getrandbits(64)
            self.assertEqual(permute(permute(x, IP, 64), IP_INV, 64), x)

    def test_sbox_rows_are_permutations(self):
        """Mỗi hàng của 8 hộp S (Stallings, Bảng 3.3) là một hoán vị của 0..15."""
        for i, box in enumerate(S_BOX):
            for r, row in enumerate(box):
                self.assertEqual(sorted(row), list(range(16)), f"S{i + 1} hàng {r}")

    def test_stallings_table_3_5(self):
        """Khóa con và (L_i, R_i) khớp Stallings, Bảng 3.5 (một số vòng)."""
        lines = []
        des_encrypt(0x02468ACEECA86420, 0x0F1571C947D9E859, lines.append)
        text = "\n".join(lines)
        for expected in ["IP        = 5A005A003CF03C0F",
                         "1E030F03080D2930", "0A31293432242318", "2921080B13143025",
                         "L1  = 3CF03C0F   R1  = BAD22845",
                         "L2  = BAD22845   R2  = 99E9B723"]:
            self.assertIn(expected, text)

    def test_weak_key(self):
        """K = 0 là khóa yếu: 16 khóa con đều bằng 0 nên E_K(E_K(P)) = P."""
        p = 0x0000000000000011
        self.assertEqual(des_encrypt(des_encrypt(p, 0), 0), p)

    @unittest.skipUnless(HAVE_REF, "chưa cài pycryptodome")
    def test_against_pycryptodome(self):
        rnd = random.Random(2026)
        for _ in range(N_RANDOM):
            key, plain = rnd.getrandbits(64), rnd.getrandbits(64)
            ref = RefDES.new(key.to_bytes(8, "big"), RefDES.MODE_ECB)
            expected = int.from_bytes(ref.encrypt(plain.to_bytes(8, "big")), "big")
            self.assertEqual(des_encrypt(plain, key), expected)
            self.assertEqual(des_decrypt(expected, key), plain)


class TestAES(unittest.TestCase):
    def test_known_vectors(self):
        for name, _, k, p, c in AES_VECTORS:
            with self.subTest(vector=name):
                key, plain, cipher = int(k, 16), int(p, 16), int(c, 16)
                self.assertEqual(aes_encrypt(plain, key), cipher)
                self.assertEqual(aes_decrypt(cipher, key), plain)

    def test_sbox_definition(self):
        """S(x) = Affine(x^-1) trong GF(2^8), x^-1 của 0 quy ước là 0."""
        def rotl8(b, n):
            return ((b << n) | (b >> (8 - n))) & 0xFF

        for x in range(256):
            inv = 0 if x == 0 else next(y for y in range(1, 256) if gmul(x, y) == 1)
            s = inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63
            self.assertEqual(SBOX[x], s, f"SBOX[{x:02X}]")

    @unittest.skipUnless(HAVE_REF, "chưa cài pycryptodome")
    def test_against_pycryptodome(self):
        rnd = random.Random(2026)
        for _ in range(N_RANDOM):
            key, plain = rnd.getrandbits(128), rnd.getrandbits(128)
            ref = RefAES.new(key.to_bytes(16, "big"), RefAES.MODE_ECB)
            expected = int.from_bytes(ref.encrypt(plain.to_bytes(16, "big")), "big")
            self.assertEqual(aes_encrypt(plain, key), expected)
            self.assertEqual(aes_decrypt(expected, key), plain)


if __name__ == "__main__":
    unittest.main(verbosity=2)
