# Lý thuyết mật mã 2026.1 – Cài đặt DES và AES-128

Cài đặt hai thuật toán **DES** (FIPS 46-3) và **AES-128** (FIPS-197) bằng Python thuần, **không dùng thư viện mật mã**.
Chương trình in giá trị kiểm định của **mọi trạng thái trung gian** (từng phép hoán vị, từng khóa con, từng vòng)
và được kiểm thử bằng các ví dụ trên lớp cùng các test vector chuẩn.

## Cấu trúc

| File | Nội dung |
|---|---|
| `des.py` | DES: bảng IP, IP⁻¹, E, P, PC-1, PC-2, 8 hộp S; sinh khóa con; hàm f; 16 vòng Feistel; mã hóa / giải mã |
| `aes.py` | AES-128: S-box, Rcon; SubBytes, ShiftRows, MixColumns, AddRoundKey và các phép ngược; KeyExpansion; mã hóa / giải mã |
| `common.py` | Đọc chuỗi hex, in dạng hex / nhị phân |
| `test_vectors.py` | Danh sách test vector (ví dụ trên lớp + Stallings + Grabbe + FIPS-197) |
| `main.py` | Chạy toàn bộ test vector, ghi kết quả vào `output/` |
| `test_des_aes.py` | Kiểm thử tự động (unittest) |
| `output/` | **Kết quả chạy**: giá trị từng trạng thái của mỗi test vector + bảng tổng hợp |
| `docs/GIAI_THICH.md` | Giải thích thuật toán và cách cài đặt từng hàm |

## Cách chạy

Yêu cầu Python ≥ 3.7, không cần cài thêm gì.

```bash
# Chạy tất cả test vector, ghi output/*.txt và in bảng tổng hợp
python main.py
python main.py -v          # in thêm toàn bộ trạng thái ra màn hình

# Chạy với khóa / bản rõ tùy ý (in từng trạng thái)
python des.py -k 0000000000000000 -p 0000000000000011
python des.py -k 0000000000000000 -c 799A09FB40DF6019          # giải mã
python aes.py -k 00000000000000000000000000000000 -p 00000000000000000000000000000011
python aes.py -k 0 -p 11       # chuỗi ngắn được hiểu là số, tự đệm 0 bên trái

# Kiểm thử tự động (phần so sánh chéo cần: pip install pycryptodome)
python -m unittest -v test_des_aes
```

## Kết quả kiểm định

Trích `output/TONG_HOP.txt`. "ĐÚNG" nghĩa là bản mã khớp đáp án **và** giải mã lại đúng bản rõ.

| Thuật toán | Vector | Khóa | Bản rõ | Bản mã | Kết quả |
|---|---|---|---|---|---|
| DES | Ví dụ trên lớp | `0000000000000000` | `0000000000000011` | `799A09FB40DF6019` | ĐÚNG |
| DES | Stallings | `0F1571C947D9E859` | `02468ACEECA86420` | `DA02CE3A89ECAC3B` | ĐÚNG |
| DES | Grabbe | `133457799BBCDFF1` | `0123456789ABCDEF` | `85E813540F0AB405` | ĐÚNG |
| AES-128 | Bài tập tuần 11 | `000…0000` | `000…0011` | `0410BEFCCDE6944B69DD007DEBE39A9D` | ĐÚNG |
| AES-128 | Stallings | `0F1571C947D9E8590CB7ADD6AF7F6798` | `0123456789ABCDEFFEDCBA9876543210` | `FF0B844A0853BF7C6934AB4364148FB9` | ĐÚNG |
| AES-128 | FIPS-197 phụ lục B | `2B7E151628AED2A6ABF7158809CF4F3C` | `3243F6A8885A308D313198A2E0370734` | `3925841D02DC09FBDC118597196A0B32` | ĐÚNG |
| AES-128 | FIPS-197 phụ lục C.1 | `000102030405060708090A0B0C0D0E0F` | `00112233445566778899AABBCCDDEEFF` | `69C4E0D86A7B0430D8CDB78070B4C55A` | ĐÚNG |

Kiểm thử tự động (`test_des_aes.py`, 9 bài) còn kiểm tra: IP⁻¹ là nghịch đảo của IP, giá trị từng vòng khớp
Stallings Bảng 3.5, bảng S-box AES đúng định nghĩa
(nghịch đảo trong GF(2⁸) + biến đổi affine), và so sánh chéo 200 cặp (khóa, bản rõ) ngẫu nhiên cho mỗi thuật toán
với thư viện pycryptodome.

## Bài tập tuần 11 – AES: trạng thái đầu ra vòng 1 và khóa con vòng 1

Đề: `p = 0x0000000000000011`, `k = 0x0000000000000000`. AES-128 dùng khối 128 bit nên p, k được đệm 0 bên trái:
`P = 00000000 00000000 00000000 00000011`, `K = 0`. Chi tiết đầy đủ: [`output/aes_lop_tuan11.txt`](output/aes_lop_tuan11.txt).

**Khóa con vòng 1:** w0 = w1 = w2 = w3 = `00000000`

- w4 = w0 ⊕ SubWord(RotWord(w3)) ⊕ Rcon[1] = `00000000` ⊕ `63636363` ⊕ `01000000` = `62636363`
- w5 = w1 ⊕ w4 = `62636363`, w6 = w2 ⊕ w5 = `62636363`, w7 = w3 ⊕ w6 = `62636363`
- **K1 = `62636363 62636363 62636363 62636363`**

**Vòng 0:** AddRoundKey(P, K0) với K0 = 0 nên trạng thái giữ nguyên bằng P.

**Vòng 1** (ma trận xếp theo cột):

```
Đầu vòng       SubBytes       ShiftRows      MixColumns     K1             Đầu ra vòng 1
00 00 00 00    63 63 63 63    63 63 63 63    82 63 63 63    62 62 62 62    E0 01 01 01
00 00 00 00    63 63 63 63    63 63 63 63    82 63 63 63    63 63 63 63    E1 00 00 00
00 00 00 00    63 63 63 63    63 63 63 63    5B 63 63 63    63 63 63 63    38 00 00 00
00 00 00 11    63 63 63 82    82 63 63 63    BA 63 63 63    63 63 63 63    D9 00 00 00
```

- SubBytes: S(00) = 63, S(11) = 82.
- ShiftRows: hàng 3 dịch vòng trái 3 byte nên byte 82 chuyển từ cột 3 sang cột 0.
- MixColumns cột 0 = (63, 63, 63, 82):
  2·63 = C6, 3·63 = A5, 2·82 = 1F, 3·82 = 9D, ta có
  b0 = C6⊕A5⊕63⊕82 = **82**, b1 = 63⊕C6⊕A5⊕82 = **82**, b2 = 63⊕63⊕C6⊕9D = **5B**, b3 = A5⊕63⊕63⊕1F = **BA**.
  Các cột (63, 63, 63, 63) không đổi vì 2⊕3⊕1⊕1 = 1.
- **Trạng thái đầu ra vòng 1 = `E0E138D9 01000000 01000000 01000000`**

## Bài tập tuần 10 – DES theo giáo trình Stallings

- 8 hộp S trong `des.py` được đối chiếu với **Stallings, Bảng 3.3 (Definition of DES S-Boxes)** và trùng khớp từng hàng.
  Mỗi hàng là một hoán vị của 0..15 (kiểm thử `test_sbox_rows_are_permutations`).
- Ví dụ trong **Bảng 3.5** (K = `0F1571C947D9E859`, P = `02468ACEECA86420`): chi tiết ở
  [`output/des_stallings.txt`](output/des_stallings.txt). Khóa con được in thêm theo cách viết của sách
  (8 nhóm 6 bit, mỗi nhóm 2 chữ số hex) để so trực tiếp:

| | Theo sách / chương trình |
|---|---|
| IP(P) | `5A005A00 3CF03C0F` |
| K1 | `1E030F03080D2930` |
| Vòng 1: L1, R1 | `3CF03C0F`, `BAD22845` |
| K2 | `0A31293432242318` |
| Vòng 2: L2, R2 | `BAD22845`, `99E9B723` |
| K16 | `2921080B13143025` |
| Bản mã | `DA02CE3A89ECAC3B` |

  Các giá trị này được kiểm tra trong `test_stallings_table_3_5`.

## DES với p, k của lớp

`P = 0000000000000011`, `K = 0000000000000000`. Chi tiết: [`output/des_lop_p11_k0.txt`](output/des_lop_p11_k0.txt).

- IP(P) = `0080008000000000` (bit 60 và bit 64 của P chuyển đến vị trí 9 và 25), L0 = `00800080`, R0 = `00000000`.
- K = 0 nên PC-1(K) = 0, C_i = D_i = 0 và **cả 16 khóa con K1..K16 đều bằng 0**. Đây là một *khóa yếu* của DES:
  mã hóa hai lần cho lại bản rõ, E_K(E_K(P)) = P (có trong kiểm thử `test_weak_key`).
- Vòng 1: E(R0) ⊕ K1 = 0, mỗi hộp S nhận đầu vào 000000 (hàng 0, cột 0) nên đầu ra hộp S = `EFA72C4D`,
  f = P(S) = `D8D8DBBC`, L1 = `00000000`, R1 = `D858DB3C`.
- Bản mã C = `799A09FB40DF6019`.

Muốn chạy thêm ví dụ khác trên lớp: thêm một dòng vào `test_vectors.py` rồi chạy lại `python main.py`.

## Quy ước

- DES: khối/khóa là số nguyên 64 bit; các bảng đánh số bit từ 1 = bit trái nhất (MSB), đúng như giáo trình.
- AES: trạng thái là ma trận 4×4, byte vào được xếp **theo cột** (`state[r][c] = in[r + 4c]`); chuỗi hex in ra đọc theo cột.
- Trong `des.py`, `aes.py` không dùng thư viện mật mã nào. Thư viện `pycryptodome` chỉ được dùng trong `test_des_aes.py`
  để kiểm tra chéo kết quả.
