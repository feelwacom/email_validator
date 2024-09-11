import sys
import argparse
import csv
import re
import os
import pyfiglet
import chardet
import codecs
import time
import dns.resolver  # For MX record validation
from tqdm import tqdm  # For progress bar
from termcolor import colored

# Configure stdout to handle UTF-8 encoding
sys.stdout.reconfigure(encoding='utf-8')

# Function to check if an email is valid syntactically
def is_valid_email(email):
    # Check if an email address is valid.
    if not email:
        return False

    # Define the regular expression for a valid email
    regex = r"^[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)*@[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)*(\.[a-zA-Z]{2,6})$"

    # Check for the ".@" pattern in the email
    if ".@" in email:
        return False

    # Match the email against the regex
    return re.match(regex, email) is not None

# Function to check if the domain has valid MX records
def has_mx_records(domain, retries=3, timeout=5):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    print(f"Checking MX records for domain: {domain}")

    for attempt in range(retries):
        try:
            print(f"Attempt {attempt+1}/{retries}: Resolving MX records...")
            answers = resolver.resolve(domain, 'MX')
            if answers:
                print(f"MX records found for domain: {domain}")
                return True
        except dns.resolver.NoAnswer:
            print(f"Attempt {attempt+1}/{retries}: No MX records found for domain {domain}")
            return False
        except dns.resolver.NXDOMAIN:
            print(f"Attempt {attempt+1}/{retries}: Domain {domain} does not exist")
            return False
        except dns.exception.Timeout:
            print(f"Attempt {attempt+1}/{retries}: DNS timeout for domain {domain}")
        except Exception as e:
            print(f"Attempt {attempt+1}/{retries}: Error checking MX records for domain {domain}: {e}")
    
    print(f"All attempts failed for domain: {domain}")
    return False

def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Verify, clean, and deduplicate a list of emails in a CSV file.')
    parser.add_argument('input_csv', help='Path to the input CSV file containing emails.')
    args = parser.parse_args()

    # Get input and output file names
    input_csv = args.input_csv
    output_csv_cleaned = os.path.splitext(input_csv)[0].rstrip('.csv') + '-cleaned.csv'
    output_csv_invalid = os.path.splitext(input_csv)[0].rstrip('.csv') + '-invalid.csv'
    
    with open(input_csv, 'rb') as f:
        result = chardet.detect(f.read())
        encoding = result['encoding']

    # Initialize counters and lists
    total_emails = 0
    valid_emails = 0
    invalid_emails = 0
    invalid_email_list = []
    seen_emails = set()  # Set to track unique emails

    # Process the input and output files
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

        # Find the email column index
        email_index = None
        if header:
            for col in ['email', 'emails']:
                if col in header:
                    email_index = header.index(col)
                    break
        else:
            # If there's no header, assume that the only column is the email column
            if len(next(reader)) == 1:
                email_index = 0

        if email_index is None:
            raise ValueError("No 'email' or 'emails' column found in the CSV file.")

        # Read the emails into a list for processing with a progress bar
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

            # Use tqdm to show progress for the email validation process
            for row in tqdm(email_rows, desc="Validating Emails", unit="email"):
                if not row:  # Skip empty rows
                    continue
                email = row[email_index].lower()  # Convert email to lowercase

                # Check for duplicates
                if email in seen_emails:
                    continue  # Skip duplicate emails
                seen_emails.add(email)  # Add unique email to the set

                # Validate the email's syntax
                if is_valid_email(email):
                    # Split email into local part and domain
                    local_part, domain = email.split('@')

                    # Check if the domain has MX records
                    if has_mx_records(domain):
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

    # Generate and print the summary
    time_elapsed = time.time() - start_time
    ascii_cleaned = pyfiglet.figlet_format("Cleaned!")
    print(colored(f'{ascii_cleaned}', 'cyan'))
    print(colored(f'by Degun - https://github.com/degun-osint\n\n', 'cyan'))
    print(f'➡️  Total email verified: {total_emails} in {time_elapsed:.2f} seconds.\n')
    print(colored(f'✅ Total valid emails: {valid_emails}. \n   File has been saved to {output_csv_cleaned}\n', 'green'))
    print(colored(f'❌ Total invalid emails: {invalid_emails}. \n   File has been saved to {output_csv_invalid}\n', 'red'))
    print(colored(f'Invalid email list:', 'white', 'on_red'))
    for invalid_email in invalid_email_list:
        print(invalid_email)

# Run the main function
if __name__ == '__main__':
    main()
