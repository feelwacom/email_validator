import sys
import argparse
import csv
import re
import os
import chardet
import codecs
import dns.resolver
import smtplib
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from termcolor import colored, cprint

# Configure stdout to handle UTF-8 encoding
sys.stdout.reconfigure(encoding='utf-8')

# Load blocklist function for disposable and blocked domains or emails
def load_blocklist(filepath):
    if not os.path.exists(filepath):
        print(f"Blocklist file '{filepath}' not found. Proceeding without email blocklist.")
        return set()
    
    with open(filepath, 'r') as file:
        domains_or_emails = {line.strip().lower() for line in file if line.strip()}
    
    return domains_or_emails

# Function to check if an email is valid syntactically
def is_valid_email(email):
    if not email:
        return False
    regex = r"^[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)*@[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)*(\.[a-zA-Z]{2,6})$"
    return re.match(regex, email) is not None

# Function to check if domain has valid MX records
def has_mx_records(domain, retries=3, timeout=5):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    for attempt in range(retries):
        try:
            answers = resolver.resolve(domain, 'MX')
            if answers:
                return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False
        except dns.exception.Timeout:
            continue  # Retry on timeout
        except dns.resolver.NoNameservers:
            return False
        except Exception as e:
            print(f"Error querying domain {domain}: {str(e)}")
            return False

    return False

# Function to check DMARC records for a domain
def check_dmarc(domain):
    try:
        dmarc_record = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_record, 'TXT')
        for rdata in answers:
            for txt_record in rdata.strings:
                if b'v=DMARC1' in txt_record:
                    return txt_record.decode('utf-8')
        return "No DMARC record found"
    except dns.resolver.NoAnswer:
        return "No DMARC record found"
    except dns.resolver.NXDOMAIN:
        return "Domain does not exist"
    except Exception as e:
        print(f"Error querying DMARC for {domain}: {str(e)}")
        return "Error querying DMARC"

# Function to check if email is role-based
def is_role_based(email):
    role_based_prefixes = ['admin', 'support', 'info', 'sales', 'help', 'billing']
    prefix = email.split('@')[0].lower()
    return any(prefix.startswith(role) for role in role_based_prefixes)

# Optional: SMTP verification to check if the mailbox exists
def check_smtp(email):
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_host = str(mx_records[0].exchange)
        
        # Connect to SMTP server
        server = smtplib.SMTP(timeout=10)
        server.set_debuglevel(0)
        server.connect(mx_host)
        server.helo(mx_host)
        server.mail('test@example.com')  # Sender address
        code, message = server.rcpt(email)  # Recipient address
        server.quit()

        # Check for SMTP response codes (250 means OK)
        return code == 250
    except Exception as e:
        print(f"SMTP check failed for {email}: {str(e)}")
        return False

# Main email validation function
def validate_email(email, blocklist, smtp_check=False):
    email = email.lower()
    
    # Check email syntax
    if not is_valid_email(email):
        return 'invalid_syntax'
    
    # Check blocklist
    if is_role_based(email):
        return 'role_based'
    
    # Check role-based email
    domain = email.split('@')[1].lower()
    if domain in blocklist or email in blocklist:
        return 'blocklisted'
    
    # Check MX records
    if not has_mx_records(domain):
        return 'invalid_mx'

    # Check DMARC
    dmarc_status = check_dmarc(domain)
    if 'DMARC1' not in dmarc_status:
        return 'no_dmarc'

    # Optional SMTP check
    if smtp_check:
        if not check_smtp(email):
            return 'smtp_failed'

    return 'valid'

# Function to clean and deduplicate emails
def clean_email_list(input_csv, blocklist_file, output_cleaned, output_invalid, smtp_check=False):
    # Load blocklist for disposable/blocked emails
    blocklist = load_blocklist(blocklist_file) if blocklist_file else set()

    with open(input_csv, 'rb') as f:
        result = chardet.detect(f.read())
        encoding = result['encoding']

    total_emails = 0
    valid_emails = 0
    invalid_emails = 0
    duplicate_emails = 0
    role_based_emails = 0
    blocklisted_emails = 0
    invalid_email_list = []
    seen_emails = set()

    with open(input_csv, 'rb') as input_file:
        encoding = chardet.detect(input_file.read())['encoding']
        input_file.seek(0)
        input_data = input_file.read().decode(encoding, errors='ignore')
        dialect = csv.Sniffer().sniff(input_data[:1024])
        input_file.seek(0)
        reader = csv.reader(codecs.iterdecode(input_file, encoding), dialect)

        header = next(reader, None)
        email_index = header.index('email') if header and 'email' in header else 0
        email_rows = list(reader)
        total_emails = len(email_rows)

        with open(output_cleaned, 'w', newline='') as output_cleaned_file, \
                open(output_invalid, 'w', newline='') as output_invalid_file:

            writer_cleaned = csv.writer(output_cleaned_file, dialect, quoting=csv.QUOTE_NONNUMERIC, escapechar='\\')
            writer_invalid = csv.writer(output_invalid_file, dialect, quoting=csv.QUOTE_NONNUMERIC, escapechar='\\')

            writer_cleaned.writerow(header)
            writer_invalid.writerow(header)

            with tqdm(total=total_emails, desc="Validating Emails", unit="email", colour='cyan') as pbar:
                for row in email_rows:
                    email = row[email_index].lower()
                    result = validate_email(email, blocklist, smtp_check)
                    
                    if result == 'valid':
                        valid_emails += 1
                        writer_cleaned.writerow(row)
                    else:
                        invalid_emails += 1
                        invalid_email_list.append(email)
                        writer_invalid.writerow(row)

                    pbar.update(1)

    cprint(f'Total emails verified: {total_emails}', 'cyan')
    cprint(f'✅ Total valid emails: {valid_emails}. File saved to {output_cleaned}', 'green')
    cprint(f'❌ Total invalid emails: {invalid_emails}. File saved to {output_invalid}', 'red')

# Main function
def main():
    parser = argparse.ArgumentParser(description='Clean and validate an email list with optional SMTP verification.')
    parser.add_argument('input_csv', help='Path to the input CSV file containing emails.')
    parser.add_argument('--blocklist', default='/mnt/data/email_blocklist.csv', help='Path to the email blocklist file (optional).')
    parser.add_argument('--output_cleaned', default='cleaned_emails.csv', help='Output CSV file for valid emails.')
    parser.add_argument('--output_invalid', default='invalid_emails.csv', help='Output CSV file for invalid emails.')
    parser.add_argument('--smtp_check', action='store_true', help='Enable SMTP mailbox verification.')
    args = parser.parse_args()

    clean_email_list(args.input_csv, args.blocklist, args.output_cleaned, args.output_invalid, args.smtp_check)

if __name__ == '__main__':
    main()
