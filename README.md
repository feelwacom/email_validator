
# Email List Cleaner and Validator

![image](https://github.com/user-attachments/assets/5a7717e0-8f45-477f-933c-513e38048fd0)



This Python script validates, cleans, deduplicates, and exports email lists from a CSV file. It checks for syntactically valid emails, removes duplicates, verifies MX records for domains, and filters out disposable email domains using a custom blocklist provided in an external CSV file. The result is a cleaned list of valid emails and a separate list of invalid emails.

## Features

- **Email syntax validation**: Ensures emails follow proper syntax rules.
- **MX record validation**: Verifies that email domains have valid MX records.
- **Custom blocklist**: Filters out disposable emails and spam traps using a provided blocklist.
- **Duplicate removal**: Automatically skips duplicate emails.
- **Progress bar**: Visual feedback for large email lists using `tqdm`.
- **Exports results**: Saves cleaned emails and invalid emails to separate CSV files.

## Prerequisites

Make sure you have Python installed and then install the required packages using the following:

```bash
pip install -r requirements.txt
```

The dependencies include:
- `argparse`: Command-line argument parsing.
- `csv`: Reading and writing CSV files.
- `chardet`: Auto-detecting character encodings.
- `codecs`: Handling file encodings.
- `dns.resolver`: For validating MX records.
- `pyfiglet`: For ASCII art display.
- `tqdm`: For displaying the progress bar.
- `termcolor`: For colorful console output.

## Usage

### Basic Usage:

```bash
python email_list_cleaner.py input_csv_file.csv
```

### Additional Options:

```bash
python email_list_cleaner.py input_csv_file.csv --blocklist /path/to/your/blocklist.csv
```

- `input_csv_file.csv`: The input CSV file containing email addresses.
- `--blocklist`: (Optional) Path to the email blocklist CSV file. The default is `/mnt/data/email_blocklist.csv`.

### Output:

- **Cleaned List**: `input_csv_file-cleaned.csv` – List of valid, deduplicated emails.
- **Invalid List**: `input_csv_file-invalid.csv` – List of invalid, disposable, or spam trap emails.

### Blocklist Format:

The blocklist should be a CSV file with one domain or email per line. Example:

```csv
disposable.com
tempmail.net
trapmail.com
```

## Example Workflow

1. Run the script with your input CSV file.
2. If necessary, provide a custom blocklist to filter out disposable or blocked domains.
3. Review the cleaned and invalid email lists.

## How to Contribute

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a pull request.

## Changelog

### v1.3.0 - (2024-09-16)
- **Added**: Role-based email detection (e.g., admin@, support@).
- **Added**: Dynamic detection of CSV file encoding using the chardet library for better handling of various encodings.
- **Added**: Progress tracking with tqdm for monitoring email validation.
- **Improved**: Duplicate email handling to optimize list processing and skip repeated entries.
- **Improved**: Visual output of the cleaning process using pyfiglet ASCII art.

### v1.2.0 - (2024-09-16)
- **Added**: Integration of disposable email domain blocklist (`disposable_email_blocklist.csv`).
- **Improved**: Code optimized for handling large files and blocklists.
- **Fixed**: Error handling for domain validation and encoding issues.

### v1.1.0 - (2024-09-13)
- **Added**: Support for loading a custom blocklist for disposable email domains.
- **Improved**: Optimized email validation and export process.

### v1.0.0 - (2024-09-11)
- Initial release.
- Email syntax validation, MX record validation, duplicate removal.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
