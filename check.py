'''
    report = {
        'financial_data': find_and_validate_credit_cards(main_text),
        'secrets': find_secrets(main_text),
        'system_info': find_system_info(main_text),
        'encoded_messages': decode_messages(main_text),
        'security_threats': analyze_logs(log_text),
        'normalized_data': normalize_and_validate(messy_data)
'''

domestic_file = input('Введите название файла с отчетом -->')
compair_file = input('Введите название файла с отчетом, с которым вы хотите проверить -->')

with open(domestic_file, 'r', encoding='UTF-8') as f:
    d_file = dict(f.read())

with open(compair_file, 'r', encoding='UTF-8') as f:
    c_file = dict(f.read())

d_not_exist = {}
not_exist = []

for i in list(d_file['financial_data']):
    if i not in list(c_file['financial_data']):
        not_exist.append(i)

d_not_exist['В financial_data есть у них но нет у нас:'] = not_exist


not_exist = []

for i in list(c_file['financial_data']):
    if i not in list(d_file['financial_data']):
        not_exist.append(i)

d_not_exist['В financial_data есть у нас но нет у них:'] = not_exist


not_exist = []

for i in list(d_file['secrets']):
    if i not in list(c_file['secrets']):
        not_exist.append(i)

d_not_exist['В secrets есть у них но нет у нас:'] = not_exist


not_exist = []

for i in list(c_file['secrets']):
    if i not in list(d_file['secrets']):
        not_exist.append(i)

d_not_exist['В secrets есть у нас но нет у них:'] = not_exist


not_exist = []

for i in list(d_file['system_info']):
    if i not in list(c_file['system_info']):
        not_exist.append(i)

d_not_exist['В system_info есть у них но нет у нас:'] = not_exist


not_exist = []

for i in list(c_file['system_info']):
    if i not in list(d_file['system_info']):
        not_exist.append(i)

d_not_exist['В system_info есть у нас но нет у них:'] = not_exist


not_exist = []

for i in list(d_file['encoded_messages']):
    if i not in list(c_file['encoded_messages']):
        not_exist.append(i)

d_not_exist['В encoded_messages есть у них но нет у нас:'] = not_exist


not_exist = []

for i in list(c_file['encoded_messages']):
    if i not in list(d_file['encoded_messages']):
        not_exist.append(i)

d_not_exist['В encoded_messages есть у нас но нет у них:'] = not_exist


not_exist = []

for i in list(d_file['security_threats']):
    if i not in list(c_file['security_threats']):
        not_exist.append(i)

d_not_exist['В security_threats есть у них но нет у нас:'] = not_exist


not_exist = []

for i in list(c_file['security_threats']):
    if i not in list(d_file['security_threats']):
        not_exist.append(i)

d_not_exist['В security_threats есть у нас но нет у них:'] = not_exist


for i in list(d_file['normalized_data']):
    if i not in list(c_file['normalized_data']):
        not_exist.append(i)

d_not_exist['В normalized_data есть у них но нет у нас:'] = not_exist


not_exist = []

for i in list(c_file['normalized_data']):
    if i not in list(d_file['normalized_data']):
        not_exist.append(i)

d_not_exist['В normalized_data есть у нас но нет у них:'] = not_exist


with open('report.txt', 'w', encoding='UTF-8') as f:
    f.write(str(*d_not_exist))
