require 'truemail'
require 'csv'
require 'ruby-progressbar'
require 'colorize'
require 'spf'
require 'resolv'
require 'concurrent'

# Truemail configuration for SMTP validation
Truemail.configure do |config|
  config.verifier_email = 'admincore@functionandrelation.com'
  config.verifier_domain = 'zohomail.com'
  config.connection_timeout = 2
  config.response_timeout = 2
  config.connection_attempts = 1
  config.smtp_fail_fast = true
  config.smtp_safe_check = true
  config.logger = { tracking_event: :all, stdout: true }
end

# Extract domain from email
def domain_from_email(email)
  email.split('@').last
end

# SPF Check with colorized log output
def spf_check(domain, email, progress)
  spf = SPF::Query.new
  result = spf.check(ip: '163.44.242.15', sender: email, helo: domain)

  case result.code
  when :pass
    progress.log("SPF Passed for #{email}".green)
    true
  else
    progress.log("SPF Failed for #{email}".red)
    false
  end
end

# DKIM Check with colorized log output
def dkim_check(domain, progress)
  dkim_selector = 'default'
  dkim_record = Resolv::DNS.open do |dns|
    dns.getresources("#{dkim_selector}._domainkey.#{domain}", Resolv::DNS::Resource::IN::TXT).map(&:strings).flatten.first
  end
  if dkim_record
    progress.log("DKIM Record found for #{domain}".green)
    true
  else
    progress.log("No DKIM record found for #{domain}".red)
    false
  end
end

# DMARC Check with colorized log output
def dmarc_check(domain, progress)
  dmarc_record = Resolv::DNS.open do |dns|
    dns.getresources("_dmarc.#{domain}", Resolv::DNS::Resource::IN::TXT).map(&:strings).flatten.first
  end
  if dmarc_record
    progress.log("DMARC Record found for #{domain}".green)
    true
  else
    progress.log("No DMARC record found for #{domain}".red)
    false
  end
end

# Truemail SMTP validation with port checks and detailed progress bar
def truemail_validation_with_ports(email, ports, progress)
  final_result = nil

  ports.each do |port|
    Truemail.configure { |config| config.smtp_port = port }

    progress.log("Checking #{email} on port #{port}".blue)
    result = Truemail.validate(email)

    if result.result.success
      progress.log("#{email.green}: Validation passed on port #{port}")
      final_result = result
    else
      progress.log("#{email.yellow}: Validation failed on port #{port}")
      final_result = result
    end

    # Increment the progress bar after each port check
    progress.increment
  end

  # Return the result after checking all ports
  final_result
end

# Categorize emails based on validation results
def categorize_email(result)
  if result && result.result.success
    result.result.errors.empty? ? 'valid' : 'bounce'
  else
    'invalid'
  end
end

# Validate email with SPF, DKIM, DMARC, and SMTP checks
def validate_email_with_checks(email, ports, overall_progress)
  progress = ProgressBar.create(
    title: "#{email}",
    total: 4 + ports.size, # 4 steps: SPF, DKIM, DMARC, SMTP
    format: '%t %a %B %p%% %c/%C %e'
  )

  domain = domain_from_email(email)

  # Parallel execution of checks (SMTP ports, SPF, DKIM, DMARC)
  result = Concurrent::Future.execute { truemail_validation_with_ports(email, ports, progress) }
  spf_future = Concurrent::Future.execute { spf_check(domain, email, progress) }
  dkim_future = Concurrent::Future.execute { dkim_check(domain, progress) }
  dmarc_future = Concurrent::Future.execute { dmarc_check(domain, progress) }

  [result, spf_future, dkim_future, dmarc_future].each(&:wait)

  progress.log("Email authentication checks completed for #{email}".blue)

  # Gather results
  result.value || OpenStruct.new(result: OpenStruct.new(success: false, errors: []))

  # Update the overall progress
  overall_progress.increment
end

# Improved email validation function with performance enhancements and colored logs
def validate_emails(input_file, valid_file, invalid_file, bounce_file, ports)
  total_lines = File.readlines(input_file).size
  overall_progress = ProgressBar.create(
    title: 'Overall Progress'.cyan,
    total: total_lines,
    format: '%t %a %B %p%% %c/%C %e'
  )

  CSV.open(valid_file, 'w') do |valid_csv|
    CSV.open(invalid_file, 'w') do |invalid_csv|
      CSV.open(bounce_file, 'w') do |bounce_csv|
        File.foreach(input_file) do |email|
          email.strip!
          result = validate_email_with_checks(email, ports, overall_progress)

          category = categorize_email(result)

          case category
          when 'valid'
            valid_csv << [email]
            puts "#{email.green}: valid"
          when 'bounce'
            bounce_info = result.result.errors.join(', ') if result
            bounce_csv << [email, bounce_info]
            puts "#{email.yellow}: bounced (#{bounce_info})"
          when 'invalid'
            invalid_csv << [email]
            puts "#{email.red}: invalid"
          end
        end
      end
    end
  end
end

# File paths for input and output
input_file = 'email.txt'
valid_emails_file = 'valid_emails.csv'
invalid_emails_file = 'invalid_emails.csv'
bounced_emails_file = 'bounced_email_errors.csv'

# Ports to check (25, 587, 465)
smtp_ports = [25, 587, 465]

# Validate emails and write results to files with progress
validate_emails(input_file, valid_emails_file, invalid_emails_file, bounced_emails_file, smtp_ports)

puts "Emails have been validated and results saved to the corresponding CSV files:"
puts "- Valid emails: #{valid_emails_file}".green
puts "- Bounced emails with errors: #{bounced_emails_file}".yellow
puts "- Invalid emails: #{invalid_emails_file}".red
