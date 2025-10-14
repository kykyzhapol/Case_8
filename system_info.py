import re


def find_system_info(text):
    """
    the function creates a dictionary from the data received from find_ip_info and find_email_info
    :param text:
    :return: system_info
    """

    system_info = {}
    system_info['ips'] = find_ip_info(text)

    system_info['email'] = find_email_info(text)

    return system_info


def find_ip_info(text):
    """
    the function finds all the IP addresses in the text and creates a list from them
    :param text:
    :return: ip_info
    """

    ip_info = []

    num_1 = r'[0-9]'
    num_2 = r'[1-9][0-9]'
    num_3_1 = r'1[0-9][0-9]'
    num_3_2 = r'2[0-4][0-9]'
    num_3_3 = r'25[0-5]'
    num = fr'{num_3_3}|{num_3_2}|{num_3_1}|{num_2}|{num_1}'
    reg_ex_1 = fr'(({num})[.]({num})[.]({num})[.]({num_1}))'
    reg_ex_2 = fr'(({num})[.]({num})[.]({num})[.]({num_2}))'
    reg_ex_3 = fr'(({num})[.]({num})[.]({num})[.]({num}))'

    reg_all = fr'(?=({reg_ex_1}))'
    for r_item in finditer(reg_all, text):
        ip_info.append(r_item.group(1))

    reg_all = fr'(?=({reg_ex_2}))'
    for r_item in finditer(reg_all, text):
        ip_info.append(r_item.group(1))

    reg_all = fr'(?=({reg_ex_3}))'
    for r_item in finditer(reg_all, text):
        ip_info.append(r_item.group(1))

    ip_info = list(set(ip_info))
    return ip_info


def find_email_info(text):
    """
    the function searches for email addresses in the text and creates a list of them
    :param text:
    :return: email_info
    """

    email_info = []

    num = r'[0-9]'
    symbols = r"[-_.?!~*'()`]+"
    letters_low = r'[a-z]'
    letters_up = r'[A-Z]'
    reg_ex = fr'({num}|{letters_low}|{letters_up}|{symbols})+'
    reg_all = fr'(?=(({reg_ex})@securecorp.com))'

    for r_item in finditer(reg_all, text):
        email_info.append(r_item.group(1))

    email_info = list(set(email_info))

    return email_info
