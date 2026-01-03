# frozen_string_literal: true

require_relative 'webrisk_hash/version'

require 'addressable/uri'
require 'digest'
require 'uri'

module WebriskHash
  require_relative 'webrisk_hash/canonicalizer'
  require_relative 'webrisk_hash/suffixes'
  require_relative 'webrisk_hash/hash'
  require_relative 'webrisk_hash/prefixes'

  extend WebriskHash::Canonicalizer
  extend WebriskHash::Suffixes
  extend WebriskHash::Hash
  extend WebriskHash::Prefixes
end
