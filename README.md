# WebriskHash

This Ruby gem implements the URL hashing and canonicalization algorithm described in
the Google Web Risk documentation: https://cloud.google.com/web-risk/docs/urls-hashing

## Overview

The Web Risk API uses URL hashing to check URLs against threat lists. This gem implements
the complete hashing process:

1. **Canonicalization** - Normalize URLs by removing fragments, resolving percent-encoding,
   normalizing IP addresses, and more
2. **Suffix/Prefix Generation** - Create up to 30 host/path combinations from each URL
3. **Hash Computation** - Generate SHA256 hashes for each combination
4. **Prefix Extraction** - Extract hash prefixes (4-32 bytes) for efficient lookup

## Features

- **URL Canonicalization** (`WebriskHash.canonicalize`)
  - Removes tab (0x09), CR (0x0d), LF (0x0a) characters
  - Removes URL fragments
  - Repeatedly percent-unescapes URLs until no more escapes remain
  - Normalizes IP addresses (decimal, hex, octal, and dotted variants)
  - Converts Internationalized Domain Names (IDN) to ASCII (Punycode)
  - Resolves path segments (/../ and /./)
  - Collapses consecutive slashes in paths
  - Removes default ports (80 for HTTP, 443 for HTTPS)
  - Percent-escapes characters <= ASCII 32, >= 127, #, and %
  - Preserves query parameters without path canonicalization

- **Suffix/Prefix Expression Generation** (`WebriskHash.suffix_postfix_expressions`)
  - Up to 5 host suffix variations (exact hostname + up to 4 from last 5 components)
  - Up to 6 path prefix variations (with/without query + progressive paths)
  - Combines to create up to 30 expressions per URL
  - IP addresses use only exact hostname (no suffix variations)
  - Handles query parameters correctly

- **SHA256 Hash Prefixes** (`WebriskHash.get_prefixes`, `WebriskHash.get_prefix_map`)
  - FIPS-180-2 compliant SHA256 hashing
  - Configurable prefix lengths (4-32 bytes = 32-256 bits)
  - Hash prefix extraction from most significant bytes

## Installation

Add to your `Gemfile`:

```ruby
gem "webrisk_hash"
```

Or install and run locally:

```bash
bundle install
```

## Usage Examples

### Basic Usage

```ruby
require "webrisk_hash"

url = "http://example.com/path/to/page?query=1"

# Step 1: Canonicalize the URL
canonical = WebriskHash.canonicalize(url)
# => "http://example.com/path/to/page?query=1"

# Step 2: Get hash prefixes (default 256 bits = 32 bytes)
prefixes = WebriskHash.get_prefixes(url)
# => #<Set: {"\xAB\xCD...(32 bytes)", ...}>

# Display as hex
puts prefixes.to_a.map { |p| p.unpack1("H*") }
```

### Working with Suffix/Prefix Expressions

```ruby
# Generate all suffix/prefix expressions for a URL
canonical = WebriskHash.canonicalize("http://a.b.c/1/2.html?param=1")
expressions = WebriskHash.suffix_postfix_expressions(canonical)

puts "Total expressions: #{expressions.size}"
expressions.each { |expr| puts "  #{expr}" }

# Output:
# Total expressions: 8
#   a.b.c/1/2.html?param=1
#   a.b.c/1/2.html
#   a.b.c/1/
#   a.b.c/
#   b.c/1/2.html?param=1
#   b.c/1/2.html
#   b.c/1/
#   b.c/
```

### Getting Hash Prefixes with Custom Length

```ruby
# Get 32-bit (4 byte) hash prefixes instead of full 256-bit hashes
prefixes_32bit = WebriskHash.get_prefixes(url, 32)

# Get detailed mapping of expressions to hashes
map = WebriskHash.get_prefix_map(url, 32)
map.each do |expression, prefix_bin|
  hex_prefix = prefix_bin.unpack1('H*')
  puts "#{expression} -> #{hex_prefix}"
end
```

### Canonicalization Examples

```ruby
# Remove control characters
WebriskHash.canonicalize("http://google.com/foo\tbar\rbaz\n2")
# => "http://google.com/foobarbaz2"

# Percent-unescape repeatedly
WebriskHash.canonicalize("http://host/%25%32%35")
# => "http://host/%25"

# Normalize IP addresses
WebriskHash.canonicalize("http://3279880203/blah")
# => "http://195.127.0.11/blah"

# Resolve path segments
WebriskHash.canonicalize("http://google.com/blah/..")
# => "http://google.com/"

# Remove fragments
WebriskHash.canonicalize("http://evil.com/foo#bar")
# => "http://evil.com/foo"

# Lowercase hostname
WebriskHash.canonicalize("http://www.GOOgle.com/")
# => "http://www.google.com/"
```

## Development

Install dependencies and run tests:

```bash
bundle install
rake spec
```

For interactive debugging use:

```bash
bin/console
```

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
