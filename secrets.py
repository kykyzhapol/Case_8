from re import *


def find_secrets(text):
    """
    this function finds all the secrets in the text and creates a list of them
    :param text:
    :return: secrets
    """

    secrets = []

    num = r'[0-9]'
    symbols = r'[-_.?!]+'
    letters = r'[a-zA-Z]'
    reg_ex = fr'({num}|{letters}|{symbols})+'

    for r_item in finditer(reg_ex, text):
        secrets.append(r_item)

    secrets = list(set(secrets))

    return secrets
