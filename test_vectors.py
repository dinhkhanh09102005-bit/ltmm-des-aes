"""Bộ test vector dùng để kiểm định DES và AES-128.

Mỗi vector: (mã_tên, mô tả, khóa, bản rõ, bản mã mong đợi)
- Vector của lớp: bản mã mong đợi lấy từ thư viện chuẩn pycryptodome (kiểm tra độc lập).
- Vector giáo trình / chuẩn: bản mã mong đợi lấy từ tài liệu gốc.
Muốn thêm ví dụ mới trên lớp: thêm 1 dòng vào danh sách tương ứng.
"""

DES_VECTORS = [
    ("lop_p11_k0",
     "Ví dụ trên lớp - Lý thuyết mật mã 2026.1: p = 0x0000000000000011, k = 0x0000000000000000",
     "0000000000000000", "0000000000000011", "799A09FB40DF6019"),
    ("stallings",
     "Stallings, Cryptography and Network Security - ví dụ DES (Bảng 3.5), S-box theo Bảng 3.3",
     "0F1571C947D9E859", "02468ACEECA86420", "DA02CE3A89ECAC3B"),
    ("grabbe",
     "J. Orlin Grabbe, The DES Algorithm Illustrated",
     "133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
]

AES_VECTORS = [
    ("lop_tuan11",
     "Bài tập tuần 11 - Lý thuyết mật mã 2026.1: p = 0x...0011, k = 0x...0000 "
     "(đệm 0 bên trái đủ 128 bit)",
     "00000000000000000000000000000000", "00000000000000000000000000000011",
     "0410BEFCCDE6944B69DD007DEBE39A9D"),
    ("stallings",
     "Stallings, Cryptography and Network Security - ví dụ AES",
     "0F1571C947D9E8590CB7ADD6AF7F6798", "0123456789ABCDEFFEDCBA9876543210",
     "FF0B844A0853BF7C6934AB4364148FB9"),
    ("fips197_b",
     "FIPS-197, Phụ lục B (Cipher Example)",
     "2B7E151628AED2A6ABF7158809CF4F3C", "3243F6A8885A308D313198A2E0370734",
     "3925841D02DC09FBDC118597196A0B32"),
    ("fips197_c1",
     "FIPS-197, Phụ lục C.1 (AES-128)",
     "000102030405060708090A0B0C0D0E0F", "00112233445566778899AABBCCDDEEFF",
     "69C4E0D86A7B0430D8CDB78070B4C55A"),
]
