# frozen_string_literal: true

module WebriskHash
  # Suffix/Prefix Expression Generation for Web Risk API
  #
  # Generates all possible host suffix and path prefix combinations for a canonicalized URL.
  # These combinations are used to create the expressions that will be hashed and checked
  # against Web Risk lists.
  #
  # The process follows the Web Risk API specification:
  # https://cloud.google.com/web-risk/docs/urls-hashing#suffixprefix-expressions
  #
  # @see https://cloud.google.com/web-risk/docs/urls-hashing#suffixprefix-expressions
  module Suffixes
    extend self

    # Generate suffix/prefix expressions for a canonicalized URL
    #
    # Returns up to 30 different host suffix and path prefix combinations.
    # Only the host and path components are used; scheme, username, password,
    # and port are discarded.
    #
    # For the host, tries at most 5 different strings:
    # 1. The exact hostname in the URL
    # 2. Up to 4 hostnames formed by starting with the last 5 components
    #    and successively removing the leading component
    # Note: Additional hostnames are not checked if the host is an IP address
    #
    # For the path, tries at most 6 different strings:
    # 1. The exact path of the URL, including query parameters
    # 2. The exact path of the URL, without query parameters
    # 3-6. The four paths formed by starting at root (/) and
    #      successively appending path components, including trailing slash
    #
    # @param canonical_url [String] The canonicalized URL
    # @return [Set<String>] Set of suffix/prefix expressions (host/path combinations)
    #
    # @example For http://a.b.c/1/2.html?param=1
    #   suffix_postfix_expressions("http://a.b.c/1/2.html?param=1")
    #   # => Set with 8 expressions:
    #   # ["a.b.c/1/2.html?param=1", "a.b.c/1/2.html", "a.b.c/", "a.b.c/1/",
    #   #  "b.c/1/2.html?param=1", "b.c/1/2.html", "b.c/", "b.c/1/"]
    #
    # @example For http://a.b.c.d.e.f.g/1.html
    #   suffix_postfix_expressions("http://a.b.c.d.e.f.g/1.html")
    #   # => Set with 10 expressions (5 host suffixes × 2 path prefixes)
    #   # Note: b.c.d.e.f.g is skipped (only last 5 components used)
    #
    # @example For http://1.2.3.4/1/
    #   suffix_postfix_expressions("http://1.2.3.4/1/")
    #   # => Set with 2 expressions:
    #   # ["1.2.3.4/1/", "1.2.3.4/"]
    #   # (IP addresses only use exact hostname)
    #
    def suffix_postfix_expressions(canonical_url)
      return Set.new unless canonical_url

      u = canonical_url.sub(%r{^[^:]+://}, '')
      host, rest = u.split('/', 2)
      path_and_query = "/#{rest || ''}"

      if path_and_query.include?('?')
        path, query = path_and_query.split('?', 2)
      else
        path = path_and_query
        query = nil
      end

      host_suffixes = generate_host_suffixes(host)
      path_prefixes = generate_path_prefixes(path, query)

      results = []
      host_suffixes.each do |h|
        path_prefixes.each do |p|
          results << (h + p)
        end
      end

      Set.new(results)
    end

    private

    def generate_host_suffixes(host)
      return [host] if ip_address?(host)

      suffixes = []
      parts = host.split('.')

      suffixes << host

      if parts.length > 1
        relevant_parts = parts.length > 5 ? parts[-5..] : parts

        (2..relevant_parts.length).each do |num_components|
          suffix = relevant_parts[-num_components..].join('.')
          suffixes << suffix unless suffix == host
          break if suffixes.length >= 5
        end
      end

      suffixes.take(5)
    end

    def generate_path_prefixes(path, query)
      prefixes = []

      prefixes << "#{path}?#{query}" if query
      prefixes << path unless prefixes.include?(path)

      if path != '/'
        segments = path.split('/').reject(&:empty?)
        current = '/'

        segments.each_with_index do |segment, index|
          break if prefixes.length >= 6

          current += segment
          current += '/' if index < segments.length - 1 || path.end_with?('/')

          prefixes << current unless prefixes.include?(current)
        end
      end

      prefixes << '/' if !prefixes.include?('/') && prefixes.length < 6

      prefixes.take(6)
    end

    def ip_address?(host)
      host =~ /^(\d+\.){3}\d+$/
    end
  end
end
