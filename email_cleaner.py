import sys
import argparse
import csv
import re
import os
import pyfiglet
import chardet
import codecs
import dns.resolver
from tqdm import tqdm
from termcolor import colored, cprint
from concurrent.futures import ThreadPoolExecutor, as_completed
import smtplib
from email_validator import validate_email, EmailNotValidError

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

# Function to check DMARC record for a domain
def get_dmarc_record(domain):
    try:
        dmarc_record = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for record in dmarc_record:
            if 'v=DMARC1' in record.to_text():
                return record.to_text()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None
    except Exception as e:
        print(f"Error querying DMARC for domain {domain}: {str(e)}")
        return None

# Function to check if an email is disposable or blocked
def is_blocked_or_disposable(email, blocklist):
    domain = email.split('@')[1].lower()
    return domain in blocklist or email in blocklist

# Function to check if email is role-based
def is_role_based(email):
    role_based_prefixes = ['admin', 'support', 'info', 'sales', 'help', 'billing']
    prefix = email.split('@')[0].lower()
    return any(prefix == role or prefix.startswith(f'{role}_') for role in role_based_prefixes)

# Function to check SMTP mailbox existence
def smtp_check(email):
    domain = email.split('@')[1]
    try:
        with smtplib.SMTP(timeout=10) as smtp:
            smtp.set_debuglevel(0)
            smtp.connect('smtp.' + domain)
            smtp.helo()
            smtp.mail('')
            code, message = smtp.rcpt(email)
            if code == 250:
                return True
            else:
                return False
    except Exception as e:
        print(f"SMTP check failed for {email}: {str(e)}")
        return False

# Function to clean and deduplicate emails
def clean_email_list(input_csv, blocklist_file, output_cleaned, output_invalid, smtp_check_enabled=False):
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

        with open(output_cleaned, 'w', newline='') as output_cleaned_file, \
                open(output_invalid, 'w', newline='') as output_invalid_file:

            writer_cleaned = csv.writer(output_cleaned_file, dialect, quoting=csv.QUOTE_NONNUMERIC, escapechar='\\')
            writer_invalid = csv.writer(output_invalid_file, dialect, quoting=csv.QUOTE_NONNUMERIC, escapechar='\\')

            if header:
                writer_cleaned.writerow(header)
                writer_invalid.writerow(header)

            # Step 1: Syntactic email validation
            cprint("Step 1: Validating email formats", 'cyan')
            with tqdm(total=total_emails, desc="Validating Email Formats", unit="email", colour='cyan') as pbar:
                for row in email_rows:
                    if not row:
                        continue
                    email = row[email_index].lower()

                    if email in seen_emails:
                        duplicate_emails += 1
                        continue
                    seen_emails.add(email)

                    if is_valid_email(email):
                        pbar.update(1)
                    else:
                        invalid_emails += 1
                        invalid_email_list.append(email)
                        writer_invalid.writerow(row)

            # Step 2: Blocklist and disposable email check
            cprint("Step 2: Checking against blocklist", 'yellow')
            with tqdm(total=total_emails, desc="Checking Blocklist", unit="email", colour='yellow') as pbar:
                for row in email_rows:
                    email = row[email_index].lower()

                    if is_blocked_or_disposable(email, blocklist):
                        blocklisted_emails += 1
                        invalid_emails += 1
                        invalid_email_list.append(email)
                        writer_invalid.writerow(row)
                    else:
                        pbar.update(1)

            # Step 3: Role-based email check
            cprint("Step 3: Checking for role-based emails", 'magenta')
            actual_rows_processed = 0  # Debugging count

            with tqdm(total=total_emails, desc="Checking Role-Based Emails", unit="email", colour='magenta') as pbar:
                for row in email_rows:
                    if not row or len(row) <= email_index:  # Skip empty rows or rows with missing email column
                        continue

                    email = row[email_index].lower()

                    actual_rows_processed += 1  # Count only actual processed rows

                    if is_role_based(email):
                        role_based_emails += 1
                        invalid_emails += 1
                        invalid_email_list.append(email)
                        writer_invalid.writerow(row)
                    
                    pbar.update(1)

            # After the loop, compare processed rows
            print(f"Total emails: {total_emails}, Rows actually processed: {actual_rows_processed}")

            # Step 4: MX record check
            cprint("Step 4: Checking MX records", 'green')
            with tqdm(total=total_emails, desc="Checking MX Records", unit="email", colour='green') as pbar:
                for row in email_rows:
                    email = row[email_index].lower()
                    domain = email.split('@')[1].lower()

                    if has_mx_records(domain):
                        valid_emails += 1
                        writer_cleaned.writerow(row)
                    else:
                        invalid_emails += 1
                        invalid_email_list.append(email)
                        writer_invalid.writerow(row)
                    pbar.update(1)

            # Step 5: DMARC record check
            cprint("Step 5: Checking DMARC records", 'blue')
            with tqdm(total=total_emails, desc="Checking DMARC Records", unit="email", colour='blue') as pbar:
                for row in email_rows:
                    email = row[email_index].lower()
                    domain = email.split('@')[1].lower()

                    dmarc_record = get_dmarc_record(domain)
                    if dmarc_record:
                        valid_emails += 1
                        writer_cleaned.writerow(row)
                    else:
                        invalid_emails += 1
                        invalid_email_list.append(email)
                        writer_invalid.writerow(row)
                    pbar.update(1)

            if smtp_check_enabled:
                # Step 6: SMTP check
                cprint("Step 6: Checking SMTP mailboxes", 'red')
                with ThreadPoolExecutor(max_workers=10) as executor:
                    future_to_email = {executor.submit(smtp_check, row[email_index].lower()): row for row in email_rows}
                    for future in as_completed(future_to_email):
                        email = future_to_email[future][email_index].lower()
                        try:
                            is_valid = future.result()
                            if not is_valid:
                                invalid_emails += 1
                                invalid_email_list.append(email)
                                writer_invalid.writerow(future_to_email[future])
                        except Exception as e:
                            print(f"SMTP check error for {email}: {str(e)}")
                        pbar.update(1)

    ascii_cleaned = pyfiglet.figlet_format("Cleaned!")
    print(colored(f'{ascii_cleaned}', 'cyan'))
    print(f'Total emails verified: {total_emails}.')
    print(colored(f'✅ Total valid emails: {valid_emails}. File saved to {output_cleaned}', 'green'))
    print(colored(f'❌ Total invalid emails: {invalid_emails}. File saved to {output_invalid}', 'red'))
    print(colored(f'🟡 Total duplicate emails: {duplicate_emails}', 'yellow'))
    print(colored(f'🟠 Total role-based emails: {role_based_emails}', 'yellow'))
    print(colored(f'🔴 Total blocklisted emails: {blocklisted_emails}', 'yellow'))

    # Print invalid email list
    print(colored(f'Invalid email list:', 'white', 'on_red'))
    for invalid_email in invalid_email_list:
        print(invalid_email)

# Main function
def main():
    parser = argparse.ArgumentParser(description='Clean and validate an email list.')
    parser.add_argument('input_csv', help='Path to the input CSV file containing emails.')
    parser.add_argument('--blocklist', default='/mnt/data/email_blocklist.csv', help='Path to the email blocklist file (optional).')
    parser.add_argument('--output_cleaned', default='cleaned_emails.csv', help='Output CSV file for valid emails.')
    parser.add_argument('--output_invalid', default='invalid_emails.csv', help='Output CSV file for invalid emails.')
    parser.add_argument('--smtp_check', action='store_true', help='Enable SMTP verification for email addresses.')
    args = parser.parse_args()

    clean_email_list(args.input_csv, args.blocklist, args.output_cleaned, args.output_invalid, args.smtp_check)

if __name__ == '__main__':
    main()
