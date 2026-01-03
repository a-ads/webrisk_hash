# frozen_string_literal: true

module WebriskHash
  module Hash
    extend self

    # Compute SHA256 hash and return truncated prefix
    #
    # For Web Risk, a hash prefix consists of the most significant 4-32 bytes
    # of a SHA256 hash (32 to 256 bits)
    #
    # @param str [String] The string to hash (suffix/prefix expression)
    # @param bits [Integer] Number of bits to return (will be converted to bytes)
    # @return [String] Binary string containing the hash prefix
    #
    # @example FIPS-180-2 Example B1 (32 bits)
    #   truncated_sha256_prefix("abc", 32)
    #   # => "\xBA\x78\x16\xBF" (4 bytes)
    #   # Full SHA256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    #
    # @example FIPS-180-2 Example B2 (48 bits)
    #   input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    #   truncated_sha256_prefix(input, 48)
    #   # => "\x24\x8D\x6A\x61\xD2\x06" (6 bytes)
    #   # Full SHA256: 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
    #
    def truncated_sha256_prefix(str, bits)
      len = bits / 8
      digest = ::Digest::SHA256.digest(str)
      digest.byteslice(0, len)
    end
  end
end
