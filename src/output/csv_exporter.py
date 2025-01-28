import csv
import catagorization.categorizer as cat

VENDORS = [
    "TiTAN DDS", "CoreDX", "Core DX", "Zhenrong DDS", "MilDDS", "Mil DDS", "GurumDDS", "InterCOM",
    "Fast DDS", "fastdds", "cyclonedds", "connext", "opendds"
]
# write to csv from chat-GPT
def write_to_csv_from_gpt(data, filename):
    """Writes the extracted vulnerability data to a CSV file,
    avoiding duplicates and using Gemini for categorization.
    """
    fieldnames = ['id', 'title', 'description', 'vendor', 'published',
                  'cvss_score', 'severity', 'cwe_category', 'cwe_explanation', 'cause', 'impact', 'source']
    existing_vulnerabilities = {}

    # Tente ler vulnerabilidades existentes do arquivo
    try:
        with open(filename, 'r', encoding="latin1") as csvfile:  # Use latin1 aqui
            reader = csv.DictReader(csvfile)
            # Verificar se o arquivo está vazio
            if reader.fieldnames:
                for row in reader:
                    # Lidar com a possibilidade da chave 'id' não existir
                    try:
                        existing_vulnerabilities[row['title']] = row['id'] 
                    except KeyError:
                        print(f"Aviso: A linha não possui a chave 'id': {row}")
                        # existing_vulnerabilities[row['title']] = "ID_DESCONHECIDO"
    except FileNotFoundError:
        pass

    with open(filename, 'a', newline='', encoding="utf-8") as csvfile:  # UTF-8 para a escrita
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        # Escrever o cabeçalho apenas se o arquivo estiver vazio
        if len(existing_vulnerabilities) == 0:
            writer.writeheader()

        for item in data:
            # Verificar se a vulnerabilidade já existe com base no título
            if item['title'] not in existing_vulnerabilities:
                vulnerability_data = cat.categorize_vulnerability_gpt(item['description'])
                # Filtrar vulnerabilidades que não são referentes a DDS e aos vendors especificados
                if any(vendor.lower() in item['description'].lower() for vendor in VENDORS):
                    for cwe_category, cwe_explanation, vendor, cause, impact in vulnerability_data:
                        if vendor.strip().upper() != 'UNKNOWN':
                            # Atribuir os valores ao dicionário 'item'
                            item['cwe_category'] = cwe_category
                            item['cwe_explanation'] = cwe_explanation
                            item['vendor'] = vendor
                            item['cause'] = cause
                            item['impact'] = impact

                            writer.writerow(item)
                            existing_vulnerabilities[item['title']] = item['id'] 
# write to csv from gemini/google IA
def write_to_csv_from_gemini(data, filename):
    """Writes the extracted vulnerability data to a CSV file,
    avoiding duplicates and using Gemini for categorization.
    """
    fieldnames = ['id', 'title', 'description', 'vendor', 'published',
                  'cvss_score', 'severity', 'cwe_category', 'cwe_explanation', 'cause', 'impact', 'source']
    existing_vulnerabilities = {}

    # Tente ler vulnerabilidades existentes do arquivo
    try:
        with open(filename, 'r', encoding="latin1") as csvfile:  # Use latin1 aqui
            reader = csv.DictReader(csvfile)
            # Verificar se o arquivo está vazio
            if reader.fieldnames:
                for row in reader:
                    # Lidar com a possibilidade da chave 'id' não existir
                    try:
                        existing_vulnerabilities[row['title']] = row['id'] 
                    except KeyError:
                        print(f"Aviso: A linha não possui a chave 'id': {row}")
                        # existing_vulnerabilities[row['title']] = "ID_DESCONHECIDO"
    except FileNotFoundError:
        pass
    try:    
        with open(filename, 'a', newline='', encoding="utf-8") as csvfile:  # UTF-8 para a escrita
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            # Escrever o cabeçalho apenas se o arquivo estiver vazio
            if len(existing_vulnerabilities) == 0:
                writer.writeheader()

            for item in data:
                # Verificar se a vulnerabilidade já existe com base no título
                if item['title'] not in existing_vulnerabilities:
                    vulnerability_data = cat.categorize_vulnerability_gemini(item['description'])
                    # Filtrar vulnerabilidades que não são referentes a DDS e aos vendors especificados
                    if any(vendor.lower() in item['description'].lower() for vendor in VENDORS):
                        for cwe_category, cwe_explanation, vendor, cause, impact in vulnerability_data:
                            if vendor.strip().upper() != 'UNKNOWN':
                                # Atribuir os valores ao dicionário 'item'
                                item['cwe_category'] = cwe_category
                                item['cwe_explanation'] = cwe_explanation
                                item['vendor'] = vendor
                                item['cause'] = cause
                                item['impact'] = impact

                                writer.writerow(item)
                                existing_vulnerabilities[item['title']] = item['id'] 
    except IOError as e:
        print(f"Error to open file: {e}")