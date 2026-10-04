from nex import kerberos
from binascii import hexlify


def main():
    pid = 100
    password = b"MMQea3n!fsik"
    result = kerberos.derive_kerberos_key(pid, password)
    result_hex = hexlify(result).decode()
    expected = "9ef318f0a170fb46aab595bf9644f9e1"
    
    print(f"Result  : {result_hex}")
    print(f"Expected: {expected}")
    print(f"Match: {result_hex == expected}")
    
    assert result_hex == expected, f"Mismatch: {result_hex} != {expected}"


if __name__ == "__main__":
    main()