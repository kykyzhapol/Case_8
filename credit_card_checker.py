import re


with open('input.txt', 'r', encoding='UTF-8') as f:
    file = f.read()

print(file)
def find_and_validate_credit_cards(text) -> dict:
    guess_numbers = []
    """
    Находит номера карт и проверяет их алгоритмом Луна
    Возвращает: {'valid': [], 'invalid': []}
    """

    # Алгоритм Луна для справки:
    # 1. Удаляем нецифровые символы
    # 2. Проверяем длину (16 цифр)
    # 3. Применяем алгоритм проверки

    dash_pattern = r'[\d]{4}[-][\d]{4}[-][\d]{4}[-][\d]{4}'
    underscore_pattern = r'[\d]{4}[_][\d]{4}[_][\d]{4}[_][\d]{4}'
    space_pattern = r'[\d]{4}[\' \'][\d]{4}[\' \'][\d]{4}[\' \'][\d]{4}'
    split_pattern = r'[\d]{16}'


    guess_numbers.extend(re.findall(dash_pattern, text))
    guess_numbers.extend(re.findall(underscore_pattern, text))
    guess_numbers.extend(re.findall(space_pattern, text))
    guess_numbers.extend(re.findall(split_pattern, text))
    print(guess_numbers)


    for i in range(len(guess_numbers)):
        if '-' in guess_numbers[i]:
            guess_numbers[i] = guess_numbers[i].replace('-', '')
        if '_' in guess_numbers[i]:
            guess_numbers[i] = guess_numbers[i].replace('_', '')
        if ' ' in guess_numbers[i]:
            guess_numbers[i] = guess_numbers[i].replace(' ', '')
    print(guess_numbers)


    valid = []
    invalid = []


    for numbers in guess_numbers:
        total = 0
        for i in range(16):
            digit = int(numbers[15 - i])  # Идем справа налево
            if i % 2 != 0:  # Для каждой второй цифры (начиная с предпоследней)
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit

        if total % 10 == 0:
            valid.append(numbers)
        else:
            invalid.append(numbers)


    return {'valid: ': valid, 'invalid: ': invalid}


print(find_and_validate_credit_cards(file))