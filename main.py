import pandas as pd
import re
import concurrent.futures
import os
import json
import yaml
import ipaddress
from io import StringIO
import requests

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/vnd.github.v3+json"
}

token = os.environ.get("GITHUB_TOKEN", "")
if token:
    HEADERS["Authorization"] = f"Bearer {token}"

MAP_DICT = {
    'DOMAIN-SUFFIX': 'domain_suffix',
    'HOST-SUFFIX': 'domain_suffix',
    'host-suffix': 'domain_suffix',
    'DOMAIN': 'domain',
    'HOST': 'domain',
    'host': 'domain',
    'DOMAIN-KEYWORD': 'domain_keyword',
    'HOST-KEYWORD': 'domain_keyword',
    'host-keyword': 'domain_keyword',
    'IP-CIDR': 'ip_cidr',
    'ip-cidr': 'ip_cidr',
    'IP-CIDR6': 'ip_cidr',
    'IP6-CIDR': 'ip_cidr',
    'SRC-IP-CIDR': 'source_ip_cidr',
    'GEOIP': 'geoip',
    'DST-PORT': 'port',
    'SRC-PORT': 'source_port',
    "URL-REGEX": "domain_regex",
    "DOMAIN-REGEX": "domain_regex"
}

def read_yaml_from_url(url):
    response = requests.get(url, headers=HEADERS)
    response.raise_for_status()
    return yaml.safe_load(response.text)

def read_list_from_url(url):
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200:
        return None, []
    csv_data = StringIO(response.text)
    df = pd.read_csv(csv_data, header=None, names=['pattern', 'address', 'other', 'other2', 'other3'], on_bad_lines='skip')
    rules = []
    if 'AND' in df['pattern'].values:
        and_rows = df[df['pattern'].str.contains('AND', na=False)]
        for _, row in and_rows.iterrows():
            rule = {"type": "logical", "mode": "and", "rules": []}
            pattern = ",".join(row.values.astype(str))
            components = re.findall(r'\((.*?)\)', pattern)
            for component in components:
                for keyword in MAP_DICT.keys():
                    if keyword in component:
                        match = re.search(f'{keyword},(.*)', component)
                        if match:
                            value = match.group(1)
                            rule["rules"].append({MAP_DICT[keyword]: value})
            rules.append(rule)
    filtered_rows = [row for _, row in df.iterrows() if 'AND' not in row['pattern']]
    df_filtered = pd.DataFrame(filtered_rows, columns=['pattern', 'address', 'other', 'other2', 'other3'])
    return df_filtered, rules

def is_ipv4_or_ipv6(address):
    try:
        ipaddress.IPv4Network(address)
        return 'ipv4'
    except ValueError:
        try:
            ipaddress.IPv6Network(address)
            return 'ipv6'
        except ValueError:
            return None

def parse_and_convert_to_dataframe(link):
    rules = []
    if link.endswith('.yaml') or link.endswith('.txt'):
        try:
            yaml_data = read_yaml_from_url(link)
            rows = []
            if not isinstance(yaml_data, str):
                items = yaml_data.get('payload', [])
            else:
                lines = yaml_data.splitlines()
                items = lines[0].split() if lines else []
            for item in items:
                address = item.strip("'")
                if ',' not in item:
                    pattern = 'IP-CIDR' if is_ipv4_or_ipv6(item) else ('DOMAIN-SUFFIX' if address.startswith(('+', '.')) else 'DOMAIN')
                    if pattern == 'DOMAIN-SUFFIX':
                        address = address.lstrip('+.')  
                else:
                    pattern, address = item.split(',', 1)
                    if ',' in address:
                        address = address.split(',', 1)[0]
                rows.append({'pattern': pattern.strip(), 'address': address.strip(), 'other': None})
            df = pd.DataFrame(rows, columns=['pattern', 'address', 'other'])
        except:
            df, rules = read_list_from_url(link)
    else:
        df, rules = read_list_from_url(link)
    return df, rules

def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0])
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj

def parse_list_file(link, output_directory):
    try:
        df, rules = parse_and_convert_to_dataframe(link)
        if df is None:
            return None
        df = df[~df['pattern'].str.contains('#')].reset_index(drop=True)
        df = df[df['pattern'].isin(MAP_DICT.keys())].reset_index(drop=True)
        df = df.drop_duplicates().reset_index(drop=True)
        df['pattern'] = df['pattern'].replace(MAP_DICT)

        os.makedirs(output_directory, exist_ok=True)

        result_rules = {"version": 3, "rules": []}
        domain_entries = []
        domain_suffix_entries = []
        domain_keyword_entries = []
        domain_regex_entries = []
        ip_cidr_entries = []

        grouped_data = df.groupby('pattern')['address'].apply(list).to_dict()
        rule_entry = {}

        for pattern, addresses in grouped_data.items():
            if pattern == 'domain':
                domain_entries.extend([addr.strip() for addr in addresses])
            elif pattern == 'domain_suffix':
                domain_suffix_entries.extend([addr.strip() for addr in addresses])
            elif pattern == 'domain_keyword':
                domain_keyword_entries.extend([addr.strip() for addr in addresses])
            elif pattern == 'domain_regex':
                domain_regex_entries.extend([addr.strip() for addr in addresses])
            elif pattern == 'ip_cidr':
                ip_cidr_entries.extend([addr.strip() for addr in addresses])

        if domain_entries:
            rule_entry["domain"] = list(set(domain_entries))
        if domain_suffix_entries:
            rule_entry["domain_suffix"] = list(set(domain_suffix_entries))
        if domain_keyword_entries:
            rule_entry["domain_keyword"] = list(set(domain_keyword_entries))
        if domain_regex_entries:
            rule_entry["domain_regex"] = list(set(domain_regex_entries))
        if ip_cidr_entries:
            rule_entry["ip_cidr"] = list(set(ip_cidr_entries))

        if rule_entry:
            result_rules["rules"].append(rule_entry)

        file_basename = os.path.basename(link).split('.')[0]
        file_name = os.path.join(output_directory, f"{file_basename}.json")

        with open(file_name, 'w', encoding='utf-8') as output_file:
            result_rules_str = json.dumps(sort_dict(result_rules), ensure_ascii=False, indent=2)
            result_rules_str = result_rules_str.replace('\\\\', '\\')
            output_file.write(result_rules_str)

        srs_path = file_name.replace(".json", ".srs")
        ret = os.system(f"sing-box rule-set compile --output {srs_path} {file_name}")
        if ret != 0:
            print(f"Failed to compile SRS: {srs_path}")

        print(f"Generated: {file_name} and {srs_path}")
        return file_name
    except Exception as e:
        print(f'Error fetching link, skipped: {link} , reason: {str(e)}')
        return None

def get_list_files_from_github(owner, repo, path="rule/QuantumultX"):
    base_api_url = f"https://api.github.com/repos/{owner}/{repo}/contents"
    url = f"{base_api_url}/{path}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200:
        print(f"Warning: Could not access {url} . HTTP {response.status_code}")
        return []
    contents = response.json()
    results = []
    for item in contents:
        if item["type"] == "dir":
            results.extend(get_list_files_from_github(owner, repo, item["path"]))
        elif item["type"] == "file" and item["name"].endswith(".list"):
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/master/{item['path']}"
            results.append(raw_url)
    return results

if __name__ == "__main__":
    owner = "proother"
    repo = "ios_rule_script"
    all_list_urls = get_list_files_from_github(owner, repo, path="rule/QuantumultX")
    
    print(f"Found {len(all_list_urls)} .list files in the repository.")

    output_dir = "./rule"
    os.makedirs(output_dir, exist_ok=True)

    result_file_names = []

    for link in all_list_urls:
        result_file_name = parse_list_file(link, output_directory=output_dir)
        if result_file_name:
            result_file_names.append(result_file_name)

    if not result_file_names:
        print("No files were generated.")
