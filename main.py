# Part of case-study #8 (Operation Data Shield)
# Case has been done by Mikhail Gordeev, Sergey Chirkov and Ivanov Gleb
import re
import base64
import calendar


def find_and_validate_credit_cards(text) -> dict:
    guess_numbers = []
    """
    Finds card numbers and verifies them using the Moon algorithm
    Returns: {'valid': [], 'invalid': []}
    """

    # Moon's algorithm for reference:
    #1. Deleting non-numeric characters
    # 2. Check the length (16 digits)
    #3. We apply the verification algorithm

    dash_pattern = r'[\d]{4}[-][\d]{4}[-][\d]{4}[-][\d]{4}'
    underscore_pattern = r'[\d]{4}[_][\d]{4}[_][\d]{4}[_][\d]{4}'
    space_pattern = r'[\d]{4}[\' \'][\d]{4}[\' \'][\d]{4}[\' \'][\d]{4}'
    split_pattern = r'[\d]{16}'


    guess_numbers.extend(re.findall(dash_pattern, text))
    guess_numbers.extend(re.findall(underscore_pattern, text))
    guess_numbers.extend(re.findall(space_pattern, text))
    guess_numbers.extend(re.findall(split_pattern, text))


    for i in range(len(guess_numbers)):
        if '-' in guess_numbers[i]:
            guess_numbers[i] = guess_numbers[i].replace('-', '')
        if '_' in guess_numbers[i]:
            guess_numbers[i] = guess_numbers[i].replace('_', '')
        if ' ' in guess_numbers[i]:
            guess_numbers[i] = guess_numbers[i].replace(' ', '')


    valid = []
    invalid = []


    for numbers in guess_numbers:
        total = 0
        for i in range(16):
            digit = int(numbers[15 - i])  # Go from right to left
            if i % 2 != 0:  # For every second digit (starting from the penultimate one)
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit

        if total % 10 == 0:
            valid.append(numbers)
        else:
            invalid.append(numbers)


    return {'valid: ': valid, 'invalid: ': invalid}



def find_secrets(text) -> list:
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

    for r_item in re.finditer(reg_ex, text):
        secrets.append(r_item)

    secrets = list(set(secrets))

    return secrets



def find_ip_info(text) -> list:
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
    for r_item in re.finditer(reg_all, text):
        ip_info.append(r_item.group(1))

    reg_all = fr'(?=({reg_ex_2}))'
    for r_item in re.finditer(reg_all, text):
        ip_info.append(r_item.group(1))

    reg_all = fr'(?=({reg_ex_3}))'
    for r_item in re.finditer(reg_all, text):
        ip_info.append(r_item.group(1))

    ip_info = list(set(ip_info))
    return ip_info


def find_email_info(text) -> list:
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
    reg_all = fr'(?=(({reg_ex})@({letters_low})+.com))'

    for r_item in re.finditer(reg_all, text):
        email_info.append(r_item.group(1))

    email_info = list(set(email_info))

    return email_info


def find_system_info(text) -> dict:
    """
    the function creates a dictionary from the data received from find_ip_info and find_email_info
    :param text:
    :return: system_info
    """

    system_info = {}
    system_info['ips'] = find_ip_info(text)

    system_info['email'] = find_email_info(text)

    return system_info



def decode_messages(text) -> dict:
    """
    Finds and decrypts messages
    Returns: {'base64': [], 'hex': [], 'rot13': []}

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

    base64_pattern = r'\b(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b'
    hex_pattern = r'(?:0x|\\x)?([A-Fa-f0-9]{2,})+'
    rot13_pattern = r'\b[A-Za-z]{4,}\b'

    #base64 searching
    base64_matches = re.findall(base64_pattern, text)
    for code in base64_matches:
        if code != '':
            try:
                decoded = base64.b64decode(code).decode('utf-8')
                decode_base64.append(decoded)
            except (UnicodeDecodeError, ValueError):
                continue

    #Hex searching
    hex_matches = re.findall(hex_pattern, text)
    for code in hex_matches:
        try:
            #deliting trash
            clean_hex = code.replace(' ', '').replace('0x', '').replace('\\x', '')
            #checing len, if len isn't even, it is not a hex code
            if len(clean_hex) % 2 == 0:
                decoded = bytes.fromhex(clean_hex).decode('utf-8')
                decode_hex.append(decoded)
        except (ValueError, TypeError):
            continue

    #Decoding rot13
    def rot13_decode(s):
        result = []
        for char in s:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result) #

    #search and decode rot13
    rot13_matches = re.findall(rot13_pattern, text)
    for code in rot13_matches:
        decoded = rot13_decode(code)
        decode_rot13.append(decoded)

    return {'base64': decode_base64, 'hex': decode_hex, 'rot13': decode_rot13}



def detect_sql_injections(log) -> bool:
    '''
    the function searches for signs sql injection in the text and creates a list of them
    :param log:
    :return: bool
    '''
    sql_patterns = [
        r'\-\-',
        r'((\%27)|(\')).*?(or|and)',
        r"(\b1=1\b)|(\b'a'='a'\b)",
        r'(\b"a"="a"\b)',

        r'((\%27)|(\'))?union',
        r'((\%27)|(\'))?select',
        r'((\%27)|(\'))?insert',
        r'((\%27)|(\'))?update',
        r'((\%27)|(\'))?delete',
        r'((\%27)|(\'))?drop',
        r'((\%27)|(\'))?sleep\(\d+\)',
        r'exec(\s|\+)+(s|x)p\w+'
        ]

    for pattern in sql_patterns:
            if re.search(pattern, log, re.IGNORECASE):
                return True
    return False

def detect_xss_attempts(log) -> bool:
    '''
    the function searches for signs xss attempts in the text and creates a list of them
    :param log:
    :return: bool
    '''
    xss_patterns = [
        r'<script.*?>.*?</script>',
        r'<iframe.*?>',
        r'javascript:',
        r'<img.*?src.*?=>',
        r'<svg.*?>'
        r'alert\(.*?\)',
        r'eval\(.*?\)',
        ]
    
    for pattern in xss_patterns:
            if re.search(pattern, log, re.IGNORECASE):
                return True
    return False
    

def detect_suspicious_user_agents(log) -> bool:
    '''
    the function searches for signs suspicious user agents in the text and creates a list of them
    :param log:
    :return: bool
    '''
    suspicious_agents_patterns = [
        r'bot', r'test', r'debug', r'dev', 
        r'admin', r'root', r'system', r'unknown',
        r'superuser', r'map', r'scanner', r'crawler'
        ]
    
    for pattern in suspicious_agents_patterns:
            if re.search(pattern, log, re.IGNORECASE):
                return True
    return False


def detect_failed_logins(log) -> bool:
    '''
    the function searches for failed logins in the text and creates a list of them
    :param log:
    :return: bool
    '''
    failed_login_patterns = [
            r'\s([45][0-9][0-9])\s',
            r'status.*?[45][0-9][0-9]'
            ]
    
    for pattern in failed_login_patterns:
            if re.search(pattern, log, re.IGNORECASE):
                return True
    return False


def log_analysis(log_text) -> dict:
    '''
    the function creates a dictionary from the data received from detect_sql_injections,
    detect_xss_attempts, detect_suspicious_user_agents and detect_failed_logins
    :param log_text:
    :return: dict
    '''
    sql_injections = []
    xss_attempts = []
    suspicious_user_agents = []
    failed_logins = []
    

    for log in log_text:
        if detect_sql_injections(log):
            sql_injections.append(log)

        if detect_xss_attempts(log):
            xss_attempts.append(log)
            
        if detect_suspicious_user_agents(log):
            suspicious_user_agents.append(log)

        if detect_failed_logins(log):
            failed_logins.append(log)
    

    return {
        'sql_injections: ': sql_injections, 
        'xss_attempts: ': xss_attempts, 
        'suspicious_user_agents: ': suspicious_user_agents,
        'failed_logins: ': failed_logins
    }



def normalization_and_validation_cards(text) -> dict:
    guess_numbers = []
    """
    Находит номера карт и проверяет их алгоритмом Луна
    Возвращает: {'valid': [], 'invalid': []}
    """

    dash_pattern = r'[\d]{4}[-][\d]{4}[-][\d]{4}[-][\d]{4}'
    underscore_pattern = r'[\d]{4}[_][\d]{4}[_][\d]{4}[_][\d]{4}'
    space_pattern = r'[\d]{4}[\' \'][\d]{4}[\' \'][\d]{4}[\' \'][\d]{4}'
    split_pattern = r'[\d]{16}'

    
    guess_numbers.extend(re.findall(dash_pattern, text))
    guess_numbers.extend(re.findall(underscore_pattern, text))
    guess_numbers.extend(re.findall(space_pattern, text))
    guess_numbers.extend(re.findall(split_pattern, text))

    for i in range(len(guess_numbers)):
        if '-' in guess_numbers[i]:
            guess_numbers[i] = guess_numbers[i].replace('-', '')
        if '_' in guess_numbers[i]:
            guess_numbers[i] = guess_numbers[i].replace('_', '')
        if ' ' in guess_numbers[i]:
            guess_numbers[i] = guess_numbers[i].replace(' ', '')


    valid, invalid = [], []


    for numbers in guess_numbers:
        total = 0
        for i in range(16):
            digit = int(numbers[15 - i])
            if i % 2 != 0:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit

        if total % 10 == 0:
            valid.append(numbers)
        else:
            invalid.append(numbers)


    return {'valid: ': valid, 'invalid: ': invalid}


def normalization_and_validation_phones(text) -> dict:
    guess_phones = []
    """
    Находит номера телефонов и проверяет их
    Возвращает: {'valid': [], 'invalid': []}
    """

    phones_list = re.split(',', re.sub(r'[а-яА-я: \n]', '', text))
    

    symbol_pattern = r'\b[+]?[78][-_ ]?[-_ \(]?[\d]{3}[-_ \)]?[-_ ]?[\d]{3}[-_ ]?[\d]{2}[-_ ]?[\d]{2}\b'

    for i in range(len(phones_list)):
        if re.search(symbol_pattern, phones_list[i]):
            guess_phones.append(phones_list[i])


    valid, invalid = [], []

    for i in range(len(phones_list)):
        if phones_list[i] not in guess_phones:
            invalid.append(phones_list[i])

    
    for i in range(len(guess_phones)):
        if '_' in guess_phones[i]:
            guess_phones[i] = guess_phones[i].replace('_', '')
        if '-' in guess_phones[i]:
            guess_phones[i] = guess_phones[i].replace('-', '')
        if ' ' in guess_phones[i]:
            guess_phones[i] = guess_phones[i].replace(' ', '')
        if '(' in guess_phones[i]:
            guess_phones[i] = guess_phones[i].replace('(', '')
        if ')' in guess_phones[i]:
            guess_phones[i] = guess_phones[i].replace(')', '')

        if guess_phones[i][0] == '7':
            guess_phones[i] = guess_phones[i].replace('7', '8', 1)
        if guess_phones[i][0] not in '78':
            guess_phones[i] = guess_phones[i]\
                .replace(guess_phones[i][0], '8'+guess_phones[i][0], 1)


    for i in range(len(guess_phones)):
        if len(re.findall(r'\d', guess_phones[i])) == 11:
            valid.append(guess_phones[i])
        else:
            invalid.append(guess_phones[i])


    return {'valid: ': valid, 'invalid: ': invalid}


def normalization_and_validation_dates(text) -> dict:
    guess_dates = []
    """
    Находит ааты и проверяет их
    Возвращает: {'valid': [], 'invalid': []}
    """

    dates_list = re.split(',', re.sub(r'[а-яА-я: \n]', '', text))
    names_months_dict = {'January' : 1, 'February' : 2, 'March' : 3, 'April' : 4, 'May' : 5, 'June' : 6,
              'July' : 7, 'August' : 8, 'September' : 9, 'October' : 10, 'November' : 11, 'December' : 12}


    valid, invalid = [], []
    
    for i in range(len(dates_list)):
        time_parts = re.split(r'[/._-]+', dates_list[i])
        
        for i in time_parts:
            if len(i) == 4:
                year = i

        month = time_parts[1]
        try:
            month = int(month)
        except:
            for i in range(len(names_months_dict.keys())):
                if str(month) in list(names_months_dict.keys())[i]:
                    month = names_months_dict[list(names_months_dict.keys())[i]]
        
        if month > 12:
            invalid.append(dates_list[i])
            continue


        if len(time_parts[0]) == 2:
            day = time_parts[0]
        else:
            day = time_parts[2]

        if int(day) > calendar.monthrange(int(year), month)[1]:
            invalid.append(dates_list[i])
            continue
        

        valid.append(f'{day}.{month}.{year}')


    return {'valid: ': valid, 'invalid: ': invalid}


def normalization_and_validation_inn(text) -> dict:
    guess_inn = []
    """
    Находит номера ИНН и проверяет их
    Возвращает: {'valid': [], 'invalid': []}
    """

    inn_list = re.split(',', re.sub(r'[а-яА-я: \n]', '', text))

    symbol_pattern = r'\b[\d]{4}[-_ ]?[\d]{4}[-_ ]?[\d]{4}\b'
    split_pattern = r'\b[\d]{10}\b'

    guess_inn.extend(re.findall(symbol_pattern, text))
    guess_inn.extend(re.findall(split_pattern, text))


    valid, invalid = [], []

    for i in range(len(inn_list)):
        if inn_list[i] not in guess_inn:
            invalid.append(inn_list[i])
    

    for i in range(len(guess_inn)):
        if len(re.findall(r'\d', guess_inn[i])) in (10, 12):
            valid.append(guess_inn[i])
        else:
            invalid.append(guess_inn[i])


    return {'valid: ': valid, 'invalid: ': invalid}



def normalization_and_validation_data(messy_data):
    """
    Приводит данные к единому формату и проверяет их
    Возвращает: {
        'phones': {'valid': [], 'invalid': []},
        'dates': {'normalized': [], 'invalid': []},
        'inn': {'valid': [], 'invalid': []},
        'cards': {'valid': [], 'invalid': []}
    }
    """

    phones_valid, phones_invalid = [], []
    dates_valid, dates_invalid = [], []
    inn_valid, inn_invalid = [], []
    cards_valid, cards_invalid = [], []


    phones_dict = normalization_and_validation_phones(messy_data[0])
    phones_valid = phones_dict['valid: ']
    phones_invalid = phones_dict['invalid: ']

    dates_dict = normalization_and_validation_dates(messy_data[1])
    dates_valid = dates_dict['valid: ']
    dates_invalid = dates_dict['invalid: ']

    inn_dict = normalization_and_validation_inn(messy_data[2])
    inn_valid = inn_dict['valid: ']
    inn_invalid = inn_dict['invalid: ']

    cards_dict = normalization_and_validation_cards(messy_data[3])
    cards_valid = cards_dict['valid: ']
    cards_invalid = cards_dict['invalid: ']


    return {
        'phones: ': {'valid: ': phones_valid, 'invalid: ': phones_invalid},
        'dates: ': {'normalized: ': dates_valid, 'invalid: ': dates_invalid},
        'inn: ': {'valid: ': inn_valid, 'invalid: ': inn_invalid},
        'cards: ': {'valid: ': cards_valid, 'invalid: ': cards_invalid}
    }



def generate_comprehensive_report(main_text, log_text, messy_data):
    """
    Generates a full investigation report
    """
    report = {
        'financial_data': find_and_validate_credit_cards(main_text),
        'secrets': find_secrets(main_text),
        'system_info': find_system_info(main_text),
        'encoded_messages': decode_messages(main_text),
        'security_threats': log_analysis(log_text),
        'normalized_data': normalization_and_validation_data(messy_data)
    }
    return report



def print_report(report):
    """It displays the report"""
    print("=" * 50)
    print("ОТЧЕТ ОПЕРАЦИИ 'DATA SHIELD'")
    print("=" * 50)
    
    sections = [
        ("ФИНАНСОВЫЕ ДАННЫЕ", report['financial_data']),
        ("СЕКРЕТНЫЕ КЛЮЧИ", report['secrets']),
        ("СИСТЕМНАЯ ИНФОРМАЦИЯ", report['system_info']),
        ("РАСШИФРОВАННЫЕ СООБЩЕНИЯ", report['encoded_messages']),
        ("УГРОЗЫ БЕЗОПАСНОСТИ", report['security_threats']),
        ("НОРМАЛИЗОВАННЫЕ ДАННЫЕ", report['normalized_data'])
    ]
    
    print(sections)

if __name__ == "__main__":
    with open('data_leak_sample.txt', 'r', encoding='utf-8') as f:
        main_text = f.read()
    
    with open('web_server_logs.txt', 'r', encoding='utf-8') as f:
        log_text = f.read()
        
    with open('messy_data.txt', 'r', encoding='utf-8') as f:
        messy_data = f.readlines()

    with open('export_data.txt', 'w', encoding='utf-8') as f:
        f.write(str(report))
    
    
    report = generate_comprehensive_report(main_text, log_text, messy_data)
    print_report(report)


