"""Các hàm tiện ích dùng chung cho DES và AES: đọc chuỗi hex, in hex / nhị phân."""


def parse_hex(text, n_bits, name="giá trị"):
    """Đọc chuỗi hex (cho phép có '0x' và dấu cách) thành số nguyên n_bits bit.

    Nếu chuỗi ngắn hơn n_bits/4 chữ số thì coi như một SỐ và đệm 0 bên trái
    (ví dụ 0x11 với AES-128 -> 000...0011).
    """
    s = text.strip().lower().replace(" ", "").replace("_", "")
    if s.startswith("0x"):
        s = s[2:]
    n_hex = n_bits // 4
    if len(s) == 0 or len(s) > n_hex:
        raise ValueError(f"{name} phải có tối đa {n_hex} chữ số hex, nhận được {len(s)}")
    value = int(s, 16)  # báo lỗi nếu có ký tự không phải hex
    if len(s) < n_hex:
        print(f"[!] {name} chỉ có {len(s)} chữ số hex -> đệm 0 bên trái thành {to_hex(value, n_bits)}")
    return value


def to_hex(value, n_bits):
    """Số nguyên -> chuỗi hex in hoa, đủ n_bits/4 chữ số."""
    return format(value, "0{}X".format(n_bits // 4))


def to_bin(value, n_bits, group=4):
    """Số nguyên -> chuỗi nhị phân n_bits bit, tách nhóm `group` bit cho dễ đọc."""
    b = format(value, "0{}b".format(n_bits))
    return " ".join(b[i:i + group] for i in range(0, n_bits, group))


def no_log(*args, **kwargs):
    """Hàm log 'câm' - dùng khi chỉ cần kết quả, không cần in trạng thái."""
    pass
