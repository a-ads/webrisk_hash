# frozen_string_literal: true

require 'spec_helper'

RSpec.describe WebriskHash::Prefixes do
  describe '.get_prefixes and get_prefix_map' do
    it 'generates correct hash prefixes' do
      url = 'https://google.com/a/test/index.html?abc123'
      actual = WebriskHash.get_prefixes(url, 32).map(&:bytes)
      expected = Set.new([
                           [136, 152, 30, 98],
                           [166, 49, 51, 141],
                           [184, 40, 242, 237],
                           [24, 12, 238, 174],
                           [92, 148, 141, 10]
                         ])
      expect(actual.to_set).to eq(expected)
    end

    it 'does not fail with long hostnames' do
      host = 'a' * 256
      url = "https://#{host}.com/a/test/index.html?abc123"
      expect(WebriskHash.get_prefixes(url, 32)).to eq(Set.new)
    end

    it 'returns empty array for nil canonicalization' do
      expect(WebriskHash.get_prefix_map(nil, 32)).to eq([])
    end
  end
end
