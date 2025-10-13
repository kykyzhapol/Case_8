import base64
import re

with open('input.txt', 'r', encoding='UTF-8') as f:
    file = f.read()


def decode_messages(text) -> dict:
    """
    Находит и расшифровывает сообщения
    Возвращает: {'base64': [], 'hex': [], 'rot13': []}

    In base64 encoding, the character set is [A-Z, a-z, 0-9, and + /].
    If the rest length is less than 4, the string is padded with '=' characters.
    re for base64: (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?

    re for hex code: ^[A-Z|\d]*

    re for rot13: ^[a-zA-Z]*
    """
    # Base64: VGhpcyBpcyBhIHNlY3JldCBtZXNzYWdlIQ==
    # Hex: 0x4D7950617373 или \x48\x65\x6C\x6C\x6F
    # ROT13: Gur cnffjbeq vf Summer2024!


    decode_base64 = []
    decode_hex = []
    decode_rot13 = []


    base_code = re.findall(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', file)
    hex_code = re.findall(r'[A-Z|\d|' '?]*', file)
    rot13_code = re.findall(r'[A-Za-z|' '?]*', file)


    for code_to_decode in base_code:
        if code_to_decode is not None:
            decode_base64.append(base64.b64decode(code_to_decode).decode('utf-8'))

    for code_to_decode in hex_code:
        if code_to_decode is not None:
            clean_hex = code_to_decode.replace(' ', '').lower().lstrip('0x')
            decode_hex.append(bytes.fromhex(clean_hex).decode('ascii'))

    fst_part = [chr(i) for i in range(ord('a'), ord('n'))]
    scd_part = [chr(i) for i in range(ord('n'), ord('z') + 1)]
    for code_to_decode in rot13_code:
        if code_to_decode is not None:
            decode = []
            for letter in code_to_decode:
                if letter in fst_part:
                    decode.append(scd_part[fst_part.index(letter)])
                elif letter in scd_part:
                    decode.append(fst_part[scd_part.index(letter)])
                else:
                    decode.append(' ')
            decode_rot13.append(*decode)


    return {'base64': decode_base64, 'hex': decode_hex, 'rot13': decode_rot13}