import sys
import argparse
import csv
import re
import os
import pyfiglet
import chardet
import codecs
import time
import dns.resolver
from tqdm import tqdm
from termcolor import colored

# Configure stdout to handle UTF-8 encoding
sys.stdout.reconfigure(encoding='utf-8')

# Function to load disposable email blocklist and spam trap emails from a file
def load_blocklist(filepath):
    if not os.path.exists(filepath):
        print(f"Blocklist file '{filepath}' not found. Proceeding without email blocklist.")
        return set()
    
    with open(filepath, 'r') as file:
        domains_or_emails = {line.strip().lower() for line in file if line.strip()}
    
    return domains_or_emails

# Function to check if an email is syntactically valid
def is_valid_email(email):
    if not email:
        return False

    regex = r"^[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)*@[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)*(\.[a-zA-Z]{2,6})$"
    
    if ".@" in email:
        return False

    return re.match(regex, email) is not None

# Function to check if the domain has valid MX records
def has_mx_records(domain, retries=3, timeout=5):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    for attempt in range(retries):
        try:
            answers = resolver.resolve(domain, 'MX')
            if answers:
                return True
        except dns.resolver.NoAnswer:
            return False
        except dns.resolver.NXDOMAIN:
            return False
        except dns.exception.Timeout:
            continue  # Retry on timeout
    return False

# Function to check if an email is from a disposable or blocked domain
def is_blocked_or_disposable(email, blocklist):
    domain = email.split('@')[1].lower()
    return domain in blocklist or email in blocklist

def main():
    parser = argparse.ArgumentParser(description='Verify, clean, and deduplicate a list of emails in a CSV file.')
    parser.add_argument('input_csv', help='Path to the input CSV file containing emails.')
    parser.add_argument('--blocklist', default='/mnt/data/email_blocklist.csv', help='Path to the email blocklist file (optional).')
    args = parser.parse_args()

    input_csv = args.input_csv
    output_csv_cleaned = os.path.splitext(input_csv)[0].rstrip('.csv') + '-cleaned.csv'
    output_csv_invalid = os.path.splitext(input_csv)[0].rstrip('.csv') + '-invalid.csv'
    
    # Load the blocklist (disposable domains, blocked domains, and spam trap emails) from the provided file
    blocklist = load_blocklist(args.blocklist) if args.blocklist else set()

    with open(input_csv, 'rb') as f:
        result = chardet.detect(f.read())
        encoding = result['encoding']

    total_emails = 0
    valid_emails = 0
    invalid_emails = 0
    invalid_email_list = []
    seen_emails = set()

    with open(input_csv, 'rb') as input_file:
        encoding = chardet.detect(input_file.read())['encoding']
        input_file.seek(0)
        input_data = input_file.read().decode(encoding, errors='ignore')
        dialect = csv.Sniffer().sniff(input_data[:1024])
        input_file.seek(0)
        reader = csv.reader(codecs.iterdecode(input_file, encoding), dialect)

        try:
            header = next(reader, None)
        except StopIteration:
            raise ValueError("CSV file is empty")

        email_index = None
        if header:
            for col in ['email', 'emails']:
                if col in header:
                    email_index = header.index(col)
                    break
        else:
            if len(next(reader)) == 1:
                email_index = 0

        if email_index is None:
            raise ValueError("No 'email' or 'emails' column found in the CSV file.")

        email_rows = list(reader)
        total_emails = len(email_rows)

        with open(output_csv_cleaned, 'w', newline='') as output_cleaned_file, \
                open(output_csv_invalid, 'w', newline='') as output_invalid_file:

            writer_cleaned = csv.writer(output_cleaned_file, dialect, quoting=csv.QUOTE_NONNUMERIC, escapechar='\\')
            writer_invalid = csv.writer(output_invalid_file, dialect, quoting=csv.QUOTE_NONNUMERIC, escapechar='\\')

            if header:
                writer_cleaned.writerow(header)
                writer_invalid.writerow(header)
                
            start_time = time.time()

            for row in tqdm(email_rows, desc="Validating Emails", unit="email"):
                if not row:
                    continue
                email = row[email_index].lower()

                if email in seen_emails:
                    continue
                seen_emails.add(email)

                if is_valid_email(email):
                    local_part, domain = email.split('@')

                    if is_blocked_or_disposable(email, blocklist):
                        invalid_emails += 1
                        invalid_email_list.append(email)
                        writer_invalid.writerow(row)
                    elif has_mx_records(domain):
                        valid_emails += 1
                        writer_cleaned.writerow(row)
                    else:
                        invalid_emails += 1
                        invalid_email_list.append(email)
                        writer_invalid.writerow(row)
                else:
                    invalid_emails += 1
                    invalid_email_list.append(email)
                    writer_invalid.writerow(row)

    time_elapsed = time.time() - start_time
    ascii_cleaned = pyfiglet.figlet_format("Cleaned!")
    print(colored(f'{ascii_cleaned}', 'cyan'))
    print(colored(f'by Degun - https://github.com/degun-osint\n\n', 'cyan'))
    print(f'➡️  Total emails verified: {total_emails} in {time_elapsed:.2f} seconds.\n')
    print(colored(f'✅ Total valid emails: {valid_emails}. \n   File saved to {output_csv_cleaned}\n', 'green'))
    print(colored(f'❌ Total invalid emails: {invalid_emails}. \n   File saved to {output_csv_invalid}\n', 'red'))
    print(colored(f'Invalid email list:', 'white', 'on_red'))
    for invalid_email in invalid_email_list:
        print(invalid_email)

if __name__ == '__main__':
    main()
