# frozen_string_literal: true

module WebriskHash
  module Prefixes
    extend self

    # Get hash prefix map for a URL
    #
    # Returns an array of [expression, hash_prefix] pairs for all
    # suffix/prefix expressions of the URL
    #
    # @param url [String] The URL to process
    # @param size [Integer] Hash prefix size in bits (default: 256 bits = 32 bytes)
    # @return [Array<Array>] Array of [expression, hash_prefix] pairs
    #
    # @example
    #   get_prefix_map("http://a.b.c/1/2.html?param=1")
    #   # => [
    #   #      ["a.b.c/1/2.html?param=1", "\xAB\xCD..."],
    #   #      ["a.b.c/1/2.html", "\x12\x34..."],
    #   #      ...
    #   #    ]
    #
    def get_prefix_map(url, size = 32 * 8)
      canonical = WebriskHash.canonicalize(url)
      return [] if canonical.nil?

      WebriskHash.suffix_postfix_expressions(canonical).to_a.map { |u| [u, WebriskHash::Hash.truncated_sha256_prefix(u, size)] }
    end

    # Get hash prefixes for a URL
    #
    # Returns a set of hash prefixes for all suffix/prefix expressions
    # of the URL. This is the main method used to check URLs against
    # Web Risk lists.
    #
    # @param url [String] The URL to process
    # @param size [Integer] Hash prefix size in bits (default: 256 bits = 32 bytes)
    # @return [Set<String>] Set of binary hash prefixes
    #
    # @example Get 32-bit hash prefixes
    #   get_prefixes("http://evil.com/malware", 32)
    #   # => #<Set: {"\xAB\xCD\xEF\x12", "\x34\x56\x78\x90", ...}>
    #
    # @example Get full 256-bit hashes (default)
    #   get_prefixes("http://example.com/")
    #   # => #<Set: {"\xAB\xCD...(32 bytes)", ...}>
    #
    def get_prefixes(url, size = 32 * 8)
      canonical = WebriskHash.canonicalize(url)
      return Set.new if canonical.nil?

      Set.new(WebriskHash.suffix_postfix_expressions(canonical).to_a.map do |u|
        WebriskHash::Hash.truncated_sha256_prefix(u, size)
      end)
    end
  end
end
