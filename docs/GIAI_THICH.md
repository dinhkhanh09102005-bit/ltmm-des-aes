# Giải thích thuật toán và cách cài đặt

## 1. DES (`des.py`)

### 1.1 Biểu diễn dữ liệu và phép hoán vị `permute(block, table, n_in)`

Khối 64 bit được lưu bằng **một số nguyên**. Mọi bảng của DES (IP, IP⁻¹, E, P, PC-1, PC-2) đều có cùng một dạng:
*bit thứ i của đầu ra = bit thứ `table[i]` của đầu vào*, với bit đánh số 1 là bit trái nhất. Vì vậy chỉ cần một hàm:

```python
for pos in table:
    bit = (block >> (n_in - pos)) & 1   # bit thứ pos tính từ trái
    out = (out << 1) | bit              # nối vào bên phải kết quả
```

Ví dụ: P = `...0011` có bit 60 và 64 bằng 1. Trong bảng IP, số 60 nằm ở vị trí 9 và số 64 nằm ở vị trí 25,
nên IP(P) có bit 9 và 25 bằng 1, tức `0080008000000000`.

Cùng một hàm dùng được cho bảng mở rộng (E: 32 bit thành 48 bit, có bit lặp lại) và bảng nén (PC-1: 64 bit thành 56 bit, PC-2: 56 bit thành 48 bit).

### 1.2 Sinh khóa con `generate_subkeys`

1. PC-1: bỏ 8 bit chẵn lẻ (bit 8, 16, …, 64), hoán vị 56 bit còn lại, rồi tách thành C0 (28 bit trái) và D0 (28 bit phải).
2. Ở vòng i, C và D **dịch vòng trái** `SHIFTS[i]` bit (1 bit ở vòng 1, 2, 9, 16; 2 bit ở các vòng còn lại; tổng 28 bit nên C16 = C0).
   Hàm `rotate_left_28`: `((x << n) | (x >> (28 - n))) & 0xFFFFFFF`.
3. K_i = PC-2(C_i ‖ D_i), dài 48 bit.

### 1.3 Hàm f `feistel_f(R, K)`

f(R, K) = P(S(E(R) ⊕ K)):

1. **E**: mở rộng R từ 32 bit lên 48 bit.
2. XOR với khóa con 48 bit.
3. **8 hộp S**: chia 48 bit thành 8 nhóm 6 bit b1…b6. Hàng = b1b6 (0..3), cột = b2b3b4b5 (0..15).
   Mỗi hộp cho ra 4 bit, ghép lại được 32 bit.
   Ví dụ: nhóm `011000` có hàng `00` = 0, cột `1100` = 12; tra S1[0][12] = 5 = `0101`.
4. **P**: hoán vị 32 bit.

### 1.4 Mạng Feistel `des_rounds`

```
IP → (L0, R0)
lặp i = 1..16:  L_i = R_(i-1),   R_i = L_(i-1) ⊕ f(R_(i-1), K_i)
ghép R16 ‖ L16 (đổi chỗ lần cuối) → IP⁻¹ → bản mã
```

**Giải mã** dùng đúng hàm `des_rounds` nhưng truyền khóa con theo thứ tự ngược K16..K1.
Cấu trúc Feistel tự đảo ngược được (hàm f không cần khả nghịch), nên không phải viết hàm riêng.

## 2. AES-128 (`aes.py`)

### 2.1 Trạng thái

16 byte được xếp vào ma trận 4×4 **theo cột**: byte 0..3 vào cột 0, byte 4..7 vào cột 1, … (`int_to_state`).
Hàm `log_steps` in các ma trận cạnh nhau, giống cách trình bày trong FIPS-197 phụ lục B.

### 2.2 Phép nhân trong GF(2⁸): `xtime`, `gmul`

Mỗi byte là một đa thức bậc nhỏ hơn 8 với hệ số trong {0, 1}. Phép cộng là XOR.
Phép nhân được rút gọn theo m(x) = x⁸ + x⁴ + x³ + x + 1 (`0x11B`).

- `xtime(a)` = a·{02}: dịch trái 1 bit; nếu tràn ra bit thứ 8 thì XOR với `0x11B`.
  Ví dụ: 2·82: `82` = 1000 0010, dịch trái được 1 0000 0100, tràn nên XOR với 1 0001 1011, kết quả `1F`.
- a·{03} = a·{02} ⊕ a. Ví dụ: 3·82 = 1F ⊕ 82 = `9D`.
- `gmul(a, b)` nhân tổng quát: duyệt từng bit của b; nếu bit bằng 1 thì cộng (XOR) a vào kết quả, rồi a = xtime(a).

### 2.3 Bốn phép biến đổi của một vòng

| Phép | Hàm | Mô tả | Phép ngược |
|---|---|---|---|
| SubBytes | `sub_bytes` | Thay mỗi byte x bằng SBOX[x] (hàng = 4 bit cao, cột = 4 bit thấp) | `inv_sub_bytes` dùng INV_SBOX |
| ShiftRows | `shift_rows` | Hàng r dịch vòng **trái** r byte | `inv_shift_rows`: dịch vòng **phải** |
| MixColumns | `mix_columns` | Nhân mỗi cột với ma trận [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]] | `inv_mix_columns` với ma trận [[E,B,D,9],…] |
| AddRoundKey | `add_round_key` | XOR từng byte với khóa vòng | Chính nó (XOR hai lần thì triệt tiêu) |

INV_SBOX không cần gõ tay mà được tạo từ SBOX: nếu SBOX[x] = y thì INV_SBOX[y] = x.
Bảng SBOX được kiểm tra trong `test_sbox_definition`: S(x) = affine(x⁻¹), trong đó x⁻¹ là nghịch đảo của x trong GF(2⁸).

### 2.4 Mở rộng khóa `key_expansion`

Khóa 16 byte cho 4 từ đầu w0..w3. Với i = 4..43:

```
temp = w[i-1]
nếu i chia hết cho 4:  temp = SubWord(RotWord(temp)) ⊕ Rcon[i/4]
w[i] = w[i-4] ⊕ temp
```

- RotWord: dịch vòng trái 1 byte, ví dụ [a0, a1, a2, a3] thành [a1, a2, a3, a0].
- SubWord: cho từng byte qua S-box.
- Rcon[j] = [x^(j-1), 00, 00, 00] = 01, 02, 04, 08, 10, 20, 40, 80, 1B, 36.

Khóa vòng K_r gồm 4 từ w[4r]..w[4r+3], mỗi từ là một cột. Như vậy AES-128 có 11 khóa vòng K0..K10.

### 2.5 Mã hóa `aes_encrypt` và giải mã `aes_decrypt`

```
Mã hóa:  AddRoundKey(K0)
         vòng 1..9 : SubBytes → ShiftRows → MixColumns → AddRoundKey(K_r)
         vòng 10   : SubBytes → ShiftRows → AddRoundKey(K10)      (không có MixColumns)

Giải mã: AddRoundKey(K10)
         vòng 1..9 : InvShiftRows → InvSubBytes → AddRoundKey(K_(10-r)) → InvMixColumns
         vòng 10   : InvShiftRows → InvSubBytes → AddRoundKey(K0)
```

Vòng cuối bỏ MixColumns để cấu trúc giải mã đối xứng với mã hóa. MixColumns ở vòng cuối không làm tăng độ an toàn,
vì kẻ tấn công có thể tự áp dụng phép ngược của nó lên bản mã.

## 3. Cách kiểm định

1. **Đối chiếu từng trạng thái** với lời giải mẫu: FIPS-197 phụ lục B (AES) và Grabbe (DES) có in giá trị từng vòng.
   Các file `output/aes_fips197_b.txt` và `output/des_grabbe.txt` khớp với hai tài liệu này.
2. **Đối chiếu bản mã** với đáp án của tài liệu gốc (Stallings, FIPS-197).
3. **Giải mã lại** phải ra đúng bản rõ.
4. **So sánh chéo** với một cài đặt độc lập (pycryptodome) trên 200 cặp (khóa, bản rõ) ngẫu nhiên.
