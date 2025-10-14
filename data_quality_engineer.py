import re
import calendar


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
