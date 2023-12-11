import subprocess # необходимо для определения установленных пакетов и их версий
import distro # необходимо для определения ОС
from packaging import version # необходимо для сравнения версий пакетов

#Функция чтения файла CVE.txt и определение текста по переменным через yazv.append.
#Также проверяется операционная система и её версия, если это Ubuntu 20.04, то код работает дальше.
def read_yazv(file_path):
    yazv = [] # Создаём пустой список для хранения данных, куда далее впишем инфу с файла CVE.txt

    try:
        os_info = distro.linux_distribution() # Получаем информацию об операционной системе
        os_name, os_version, _ = os_info

        # Проверяем, что операционная система - Ubuntu 20.04
        if os_name != 'Ubuntu' or os_version != '20.04':
            print("Ошибка: Не удалось определить ОС как Ubuntu 20.04.")
            return yazv

        print(f"OC определена: {os_name} {os_version}")

        with open(file_path, 'r') as file:
            for line in file: # Читаем файл построчно
                parts = line.strip().split(';') # Разделяем строку по символу ';'

                if len(parts) == 5: # Проверяем, что строка содержит 5 частей
                    cve_id, distro_name, distro_version, package_name, fixed_version = parts
                    # Добавляем словарь в список 'yazv'
                    yazv.append({ 
                        'cve_id': cve_id.split(' ')[1],  # Сплитим каждый вывод, чтобы избавиться от лишней инфы
                        'distro_name': distro_name.split(' ')[1],
                        'distro_version': distro_version.split(' ')[1],
                        'package_name': package_name.split(' ')[1],
                        'fixed_version': fixed_version.split(' ')[1]
                    })
                else:
                    print(f"Ошибка в файле CVE.txt. Ошибка в формате строки: {line}")

    except FileNotFoundError:
        print(f"Файл не найден: {file_path}")

    return yazv # Возвращаем список

#Функция для определения установленных в системе пакетов и их версий при помощи модуля subprocess.
def get_in_pack():
    in_pack = []

    try:
        # Выполняем команду dpkg-query с флагом -l, чтобы получить список установленных пакетов.
        # Перенаправляем данные в переменную в виде текста.
        result = subprocess.run(['dpkg-query', '-l'], stdout=subprocess.PIPE, text=True)
        output_lines = result.stdout.split('\n')

        # Обрабатываем вывод команды и извлекаем информацию о пакетах
        for line in output_lines[5:]:  # Начинаем с 5-й строки, чтобы пропустить заголовки команды dpkg-query
            parts = line.split() # разбиваем строку по частям пробелом
            if len(parts) >= 3: # Проверяем, что в строке есть как минимум 3 части.
                package_name = parts[1] # Извлекаем 2-й элемент
                in_version = parts[2] # Извлекаем 3-й элемент

                # Добавляем словарь в список в виде 'package_name' & 'in_version'
                in_pack.append({
                    'package_name': package_name,
                    # Сплитуем, чтобы избавиться в версии от лишней инфы и выводить только цифры
                    'in_version': in_version.split('-')[0]
                })

    except Exception as e:
        print(f"Ошибка при выполнении команды dpkg-query: {e}")

    return in_pack # Возвращаем список

# Функция сравнения установленных пакетов с заданным в БД CVE.txt
def check_yazv(yazv,in_pack):
    # Проверяем, совпадают ли package_name и installed_version < fixed_version
    for yaz in yazv: # Проходимся по каждому элементу списка yazv
        for package in in_pack: # Так же проходимся по каждому элементу

            #Проверяем, совпадают ли названия пакетов из CVE.txt и in_pack(установленные).
            #А затем сравниваем версии, если установленная меньше исправленной, то пакет является уязвимым.
            if yaz['package_name'] == package['package_name'] and version.parse(package['in_version']) < version.parse(yaz['fixed_version']):
                print(f"Найдена уязвимость: {yaz['cve_id']} в пакете {yaz['package_name']}. Установленная версия: {package['in_version']}, версия с исправлением: {yaz['fixed_version']}")
# Чтение уязвимостей с файла CVE.txt
file_path = '/home/ubuntu/Desktop/CVE.txt'
yazv = read_yazv(file_path)

# Получаем информацию об установленных пакетах
in_pack = get_in_pack()

# Осуществляем поиск уязвимых пакетов
check_yazv(yazv,in_pack)