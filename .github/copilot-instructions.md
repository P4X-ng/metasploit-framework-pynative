# GitHub Copilot Instructions for Metasploit Framework

This file provides guidance for AI coding assistants working on the Metasploit Framework.

## Project Overview

Metasploit Framework is an open-source penetration testing platform used for security research and testing. It includes exploit modules, auxiliary modules, payloads, and supporting libraries written primarily in Ruby.

## Coding Standards

### Ruby Style Guide

- Follow the [Ruby Style Guide](https://github.com/bbatsov/ruby-style-guide)
- Use [Rubocop](https://rubygems.org/search?query=rubocop) for linting
- Run `msftidy` before committing to catch common issues
- Ensure code passes all Rubocop checks

### Git Commit Guidelines

- Follow the [50/72 rule](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html) for commit messages
- Write descriptive titles (max 50 characters)
- Add detailed descriptions in the commit body (wrap at 72 characters)
- Reference related issues using `See #1234` format

## Module Development

### New Modules

When creating new modules:

- **License**: Use BSD 3-clause, BSD 2-clause, or MIT license
- **One module per PR**: Don't include multiple modules in a single pull request
- **Documentation**: Include module documentation showing sample run-throughs
- **Setup instructions**: Provide clear instructions for setting up the vulnerable environment
- **Testing**: Always test modules locally before submitting
- **Notes section**: Include required `Stability`, `Reliability`, and `SideEffects` metadata as per [module metadata guidelines](https://docs.metasploit.com/docs/development/developing-modules/module-metadata/definition-of-module-reliability-side-effects-and-stability.html)

### Module Structure

```ruby
class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Module Name',
        'Description' => %q{
          Clear description of what the module does
        },
        'Author' => ['Author Name <email@example.com>'],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', 'YYYY-NNNNN'],
          ['URL', 'https://...']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE, CRASH_SERVICE_DOWN, etc.],
          'Reliability' => [REPEATABLE_SESSION, FIRST_ATTEMPT_FAIL, etc.],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK, etc.]
        }
      )
    )
  end
end
```

### Module Mixins

- Use existing module mixins and [APIs](https://rapid7.github.io/metasploit-framework/api) when possible
- Don't reinvent functionality that already exists in the framework
- Common mixins: `Msf::Exploit::Remote::HttpClient`, `Msf::Auxiliary::Scanner`, etc.

## Testing Requirements

### RSpec Tests

- **Required for library code**: Even small changes in libraries can break existing code
- Follow [Better Specs](http://www.betterspecs.org/) guidelines
- Write clear, descriptive test cases
- Test edge cases and error conditions

### Module Testing

- Test modules in a controlled environment before submission
- Include verification steps in pull requests
- Document expected vs. observed behavior
- Provide console output examples

## Security Considerations

### Sensitive Information

- **Never** include sensitive information in code or PRs
- **Never** include externally-routable IP addresses in documentation
- **Never** commit secrets, API keys, or credentials
- Use placeholder values in examples (e.g., `192.168.1.100`, `example.com`)

### Code Safety

- Don't submit untested code from the internet
- Don't submit untested code from AI/LLM without thorough review and testing
- Validate all external inputs
- Consider security implications of changes

## Documentation

### YARD Documentation

- Write [YARD](http://yardoc.org) documentation for library code
- Document parameters, return values, and examples
- Keep documentation up-to-date with code changes

### Module Documentation

- Include [module documentation](https://docs.metasploit.com/docs/using-metasploit/basics/module-documentation.html)
- Show sample run-throughs with console output
- Document setup requirements and dependencies
- Include verification steps

## Pull Request Guidelines

### Before Submitting

- Create a topic branch (don't work directly on `master`)
- Test your code thoroughly
- Run linters and fix all warnings/errors
- Write clear, descriptive PR titles and descriptions
- Include verification steps
- Reference related issues

### PR Description Should Include

- What the PR does and why
- Console output or screenshots (if applicable)
- Verification/testing steps
- Related issue references
- Any breaking changes or migration notes

### What Not to Do

- Leave PR description blank
- Submit working but unfinished code without marking as "WIP" or draft
- Abandon PRs without responding to feedback
- Include multiple unrelated changes in one PR
- Post questions in older closed PRs

## Common Patterns and Best Practices

### Error Handling

- Use `print_error`, `print_warning`, `print_status`, `print_good` for console output
- Handle exceptions gracefully
- Provide meaningful error messages
- Clean up resources on failure

### Datastore Options

- Use descriptive option names
- Set sensible defaults when possible
- Document all options clearly
- Validate option values

### Loot Storage

```ruby
loot_name = 'descriptive-name'
loot_type = 'text/plain'  # or appropriate MIME type
loot_desc = 'Description of what this loot contains'
p = store_loot(loot_name, loot_type, datastore['RHOST'], data, loot_desc)
print_good("File saved in: #{p}")
```

## Resources

- [Metasploit Documentation](https://docs.metasploit.com/)
- [Contributing Guide](https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md)
- [Development Setup](https://docs.metasploit.com/docs/development/get-started/setting-up-a-metasploit-development-environment.html)
- [API Documentation](https://rapid7.github.io/metasploit-framework/api)
- [Module Metadata Guidelines](https://docs.metasploit.com/docs/development/developing-modules/module-metadata/definition-of-module-reliability-side-effects-and-stability.html)

## Getting Help

- [GitHub Discussions](https://github.com/rapid7/metasploit-framework/discussions)
- [Metasploit Slack](https://www.metasploit.com/slack)
- [GitHub Issues](https://github.com/rapid7/metasploit-framework/issues)

## CVE Requests

If your module describes a new vulnerability, email cve@rapid7.com for a CVE ID (include your PR number).
