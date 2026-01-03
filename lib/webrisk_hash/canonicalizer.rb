# frozen_string_literal: true

module WebriskHash
  # URL Canonicalization for Web Risk API
  #
  # Implements the canonicalization process described in the Web Risk API documentation:
  # https://cloud.google.com/web-risk/docs/urls-hashing#canonicalization
  #
  # The canonicalization process includes:
  # 1. Parse URL according to RFC 2396 (convert IDN to ASCII Punycode if needed)
  # 2. Remove tab (0x09), CR (0x0d), and LF (0x0a) characters
  # 3. Remove URL fragments
  # 4. Repeatedly percent-unescape until no more percent-escapes
  # 5. Normalize hostname:
  #    - Remove leading/trailing dots
  #    - Replace consecutive dots with single dot
  #    - Parse and normalize IP addresses (handle octal, hex, decimal)
  #    - Lowercase the entire hostname
  # 6. Canonicalize path:
  #    - Resolve /../ and /./ sequences
  #    - Replace consecutive slashes with single slash
  # 7. Percent-escape characters <= ASCII 32, >= 127, #, and %
  # 8. Do NOT apply path canonicalization to query parameters
  # 9. Remove default ports (80 for HTTP, 443 for HTTPS)
  #
  # @see https://cloud.google.com/web-risk/docs/urls-hashing#canonicalization
  module Canonicalizer
    extend self

    # Canonicalize a URL according to Web Risk API specification
    #
    # @param url [String] The URL to canonicalize
    # @return [String, nil] The canonicalized URL or nil if invalid
    #
    # @example
    #   canonicalize("http://host/%25%32%35")
    #   # => "http://host/%25"
    #
    #   canonicalize("http://www.GOOgle.com/")
    #   # => "http://www.google.com/"
    #
    #   canonicalize("http://3279880203/blah")
    #   # => "http://195.127.0.11/blah"
    #
    def canonicalize(url)
      return nil if url.nil?

      raw = url.dup.force_encoding(Encoding::BINARY)
      raw = raw.gsub(/[\t\r\n]/, '')
      raw = raw.sub(/\A +/n, '').sub(/ +\z/n, '')
      url_with_scheme = raw.include?('://') ? raw : "http://#{raw}"
      url_with_scheme = url_with_scheme.gsub(%r{(?<=://)([^/]*)}) { |auth| auth.gsub(' ', '%20') }

      begin
        a = Addressable::URI.parse(url_with_scheme)
      rescue StandardError
        return nil
      end

      schema = a.scheme
      if a.user
        a.user + (a.password ? ":#{a.password}" : '')
      end
      host = a.host
      after_scheme = url_with_scheme.sub(%r{\A[^:]+://}, '')
      slash_idx = after_scheme.index('/')
      path_and_query = slash_idx ? after_scheme[slash_idx..] : '/'

      path_and_query = path_and_query.split('#', 2)[0]

      if path_and_query.include?('?')
        raw_path, raw_query = path_and_query.split('?', 2)
      else
        raw_path = path_and_query
        raw_query = nil
      end
      path = raw_path && !raw_path.empty? ? raw_path : '/'
      query = raw_query

      return nil if schema.nil? || host.nil? || host.length > 255

      host_decoded = custom_decode_uri_component(normalize_ip_address(host)).gsub(/[\t\x0a\x0d]/, '')

      begin
        host_ascii = if /[^\x00-\x7F]/.match?(host_decoded)
                       Addressable::IDNA.to_ascii(host_decoded)
                     else
                       host_decoded
                     end
      rescue StandardError
        host_ascii = host_decoded
      end

      normalized_host = webrisk_uri_escape(host_ascii)
      normalized_host = normalized_host.squeeze('.').gsub(/\A\.+|\.+\z/, '').downcase

      normalized_path = normalize_component_encoding(normalize_dots_in_paths(path))
      normalized_path = "#{normalized_path}/" if path.end_with?('/') && !normalized_path.end_with?('/')

      normalized_query = query ? "?#{query}" : ''

      "#{schema}://#{normalized_host}#{normalized_path}#{normalized_query}"
    end

    def int2ip(ip_int)
      num = ip_int.to_i
      [(num >> 24) & 255, (num >> 16) & 255, (num >> 8) & 255, num & 255].join('.')
    end

    def normalize_ip_address(c)
      begin
        parts = c.split('.')
        parse_part = lambda do |p|
          if /^0x/i.match?(p)
            Integer(p)
          elsif p =~ /^0[0-9]+$/ && p.length > 1
            Integer(p, 8)
          else
            Integer(p)
          end
        end

        if parts.length == 1
          n = parse_part.call(parts[0])
          return int2ip(n) if n.between?(0, 0xFFFFFFFF)
        elsif parts.length <= 4 && parts.all? { |p| p =~ /^([0-9]+|0x[0-9a-fA-F]+|0[0-7]*)$/ }
          nums = parts.map { |p| parse_part.call(p) }
          ip_int = case nums.length
                   when 1
                     nums[0]
                   when 2
                     (nums[0] << 24) | (nums[1] & 0xFFFFFF)
                   when 3
                     (nums[0] << 24) | ((nums[1] & 0xFF) << 16) | (nums[2] & 0xFFFF)
                   when 4
                     (nums[0] << 24) | ((nums[1] & 0xFF) << 16) | ((nums[2] & 0xFF) << 8) | (nums[3] & 0xFF)
                   end
          return int2ip(ip_int) if ip_int.between?(0, 0xFFFFFFFF)
        end
      rescue StandardError
        nil
      end
      c
    end

    def normalize_component_encoding(c)
      value = c
      prev_value = nil
      1000.times do
        prev_value = value
        value = custom_decode_uri_component(prev_value).gsub(/[\t\x0a\x0d]/, '')
        break if value == prev_value
      end
      webrisk_uri_escape(value)
    end

    def normalize_dots_in_paths(path)
      segments = path.split('/')
      new_segments = []
      empty_or_dot = ['', '.'].freeze
      segments.each do |seg|
        next if empty_or_dot.include?(seg)

        if seg == '..'
          new_segments.pop unless new_segments.empty?
        else
          new_segments << seg
        end
      end
      result = "/#{new_segments.join('/')}"
      result == '' ? '/' : result
    end

    def custom_decode_uri_component(input)
      replace_map = { '%FE%FF' => "\uFFFD\uFFFD", '%FF%FE' => "\uFFFD\uFFFD" }
      multi_matcher = /((?:%[a-f0-9]{2})+)/i
      input.scan(multi_matcher).flatten.each do |match|
        replace_map[match] = URI.decode_www_form_component(match)
      rescue StandardError
        decoded = safe_decode(match)
        replace_map[match] = decoded if decoded != match
      end
      replace_map['%C2'] = "\uFFFD"
      replace_map.each do |k, v|
        input = input.gsub(Regexp.new(Regexp.escape(k), Regexp::IGNORECASE), v)
      end
      input
    end

    def safe_decode(input)
      tokens = input.scan(/%[a-f0-9]{2}/i).map { |t| t }
      (1..tokens.length).each do |split|
        left = tokens[0, split]
        right = tokens[split..] || []
        begin
          return URI.decode_www_form_component((left + right).join)
        rescue StandardError
          next
        end
      end
      input
    end

    def escape_character(code)
      chr = code.chr(Encoding::UTF_8)
      if code < 256
        if code < 16
          format('%%%02X', code)
        elsif code <= 32 || code > 127 || chr == '%' || chr == '#'
          format('%%%02X', code)
        else
          chr
        end
      else
        escape_character(code >> 8) + escape_character(code % 256)
      end
    end

    def webrisk_uri_escape(s)
      out = +''
      i = 0
      while i < s.length
        c = s[i]
        if c == '%' && s[i + 1] && s[i + 2] && s[(i + 1)..(i + 2)] =~ /^[0-9a-fA-F]{2}$/
          out << '%' << s[(i + 1)..(i + 2)].upcase
          i += 3
          next
        end
        out << escape_character(c.ord)
        i += 1
      end
      out
    end
  end
end
