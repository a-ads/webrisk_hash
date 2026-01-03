# frozen_string_literal: true

require 'spec_helper'

RSpec.describe WebriskHash::Hash do
  describe '.truncated_sha256_prefix' do
    it 'matches FIPS examples (32 bits)' do
      input = 'abc'
      out = WebriskHash.truncated_sha256_prefix(input, 32)
      expect(out.bytesize).to eq(4)
      expect(out.bytes[0, 4]).to eq([0xba, 0x78, 0x16, 0xbf])
    end

    it 'matches FIPS example (48 bits)' do
      input = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
      out = WebriskHash.truncated_sha256_prefix(input, 48)
      expect(out.bytesize).to eq(6)
      expect(out.bytes[0, 6]).to eq([0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06])
    end

    it "matches FIPS example (96 bits for million a's)" do
      input = 'a' * 1_000_000
      out = WebriskHash.truncated_sha256_prefix(input, 96)
      expect(out.bytesize).to eq(12)
      expect(out.bytes[0, 12]).to eq([0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2])
    end

    it 'returns empty string for 0 bits' do
      out = WebriskHash.truncated_sha256_prefix('abc', 0)
      expect(out.bytesize).to eq(0)
      expect(out).to eq('')
    end

    it 'handles non-multiple-of-8 bits by truncating to full bytes' do
      out = WebriskHash.truncated_sha256_prefix('abc', 20) # 20 bits -> 2 bytes
      expect(out.bytesize).to eq(2)
    end
  end
end
