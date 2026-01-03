# frozen_string_literal: true

require 'spec_helper'

RSpec.describe WebriskHash::Canonicalizer do
  describe '.canonicalize' do
    it 'returns nil for nil input' do
      expect(WebriskHash.canonicalize(nil)).to be_nil
    end

    it 'returns nil for empty string' do
      expect(WebriskHash.canonicalize('')).to be_nil
    end

    it 'decodes percent-encoded sequences' do
      expect(WebriskHash.canonicalize('http://host/%25%32%35')).to eq('http://host/%25')
    end

    it 'decodes multiple percent-encodings' do
      expect(WebriskHash.canonicalize('http://host/%25%32%35%25%32%35')).to eq('http://host/%25%25')
    end

    it 'returns nil for mailto URLs' do
      expect(
        WebriskHash.canonicalize(
          'mailto:info@example.com?&subject=&cc=&bcc=&body=' \
          'https://drive.google.com/drive/folders/aaaaa-?usp=sharing%0ABBBBB'
        )
      ).to be_nil
    end

    it 'decodes nested percent-encodings' do
      expect(WebriskHash.canonicalize('http://host/%2525252525252525')).to eq('http://host/%25')
    end

    it 'decodes percent-encoding in the middle of the path' do
      expect(WebriskHash.canonicalize('http://host/asdf%25%32%35asd')).to eq('http://host/asdf%25asd')
    end

    it 'escapes stray percent characters' do
      expect(WebriskHash.canonicalize('http://host/%%%25%32%35asd%%')).to eq('http://host/%25%25%25asd%25%25')
    end

    it 'returns unchanged for a simple URL' do
      expect(WebriskHash.canonicalize('http://www.google.com/')).to eq('http://www.google.com/')
    end

    it 'decodes percent-encoded IP in the host' do
      input = 'http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/'
      expect(WebriskHash.canonicalize(input)).to eq('http://168.188.99.26/.secure/www.ebay.com/')
    end

    it 'does not decode percent-encoded path for IP hosts' do
      input = 'http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/'
      expect(WebriskHash.canonicalize(input)).to eq(input)
    end

    it 'decodes percent-encoding in hostname and path' do
      input = 'http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B'
      expect(WebriskHash.canonicalize(input)).to eq('http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+')
    end

    it 'converts integer IP encoding to dotted-quad form' do
      expect(WebriskHash.canonicalize('http://3279880203/blah')).to eq('http://195.127.0.11/blah')
    end

    it 'removes /.. path segments' do
      expect(WebriskHash.canonicalize('http://www.google.com/blah/..')).to eq('http://www.google.com/')
    end

    it 'resolves multiple /.. segments correctly' do
      expect(WebriskHash.canonicalize('http://www.google.com/qwe/rty/blah/../..')).to eq('http://www.google.com/qwe')
    end

    it 'adds http scheme when missing' do
      expect(WebriskHash.canonicalize('www.google.com/')).to eq('http://www.google.com/')
    end

    it 'adds http scheme when missing (no path)' do
      expect(WebriskHash.canonicalize('www.google.com')).to eq('http://www.google.com/')
    end

    it 'removes URL fragment' do
      expect(WebriskHash.canonicalize('http://www.evil.com/blah#frag')).to eq('http://www.evil.com/blah')
    end

    it 'downcases the hostname' do
      expect(WebriskHash.canonicalize('http://www.GOOgle.com/')).to eq('http://www.google.com/')
    end

    it 'removes trailing dots from hostname' do
      expect(WebriskHash.canonicalize('http://www.google.com.../')).to eq('http://www.google.com/')
    end

    it 'collapses consecutive dots in hostname' do
      expect(WebriskHash.canonicalize('http://www...google...com/')).to eq('http://www.google.com/')
    end

    it 'removes control characters from the path' do
      expect(WebriskHash.canonicalize("http://www.google.com/foo\tbar\rbaz\n2")).to eq('http://www.google.com/foobarbaz2')
    end

    it 'keeps a trailing question mark in the URL' do
      expect(WebriskHash.canonicalize('http://www.google.com/q?')).to eq('http://www.google.com/q?')
    end

    it 'preserves question marks in query segments' do
      expect(WebriskHash.canonicalize('http://www.google.com/q?r?')).to eq('http://www.google.com/q?r?')
    end

    it 'preserves multiple question marks in path/query' do
      expect(WebriskHash.canonicalize('http://www.google.com/q?r?s')).to eq('http://www.google.com/q?r?s')
    end

    it 'removes multiple fragment markers' do
      expect(WebriskHash.canonicalize('http://evil.com/foo#bar#baz')).to eq('http://evil.com/foo')
    end

    it 'preserves semicolon at end of path' do
      expect(WebriskHash.canonicalize('http://evil.com/foo;')).to eq('http://evil.com/foo;')
    end

    it 'preserves semicolon in query' do
      expect(WebriskHash.canonicalize('http://evil.com/foo?bar;')).to eq('http://evil.com/foo?bar;')
    end

    it 'percent-encodes invalid hostname bytes' do
      expect(WebriskHash.canonicalize("http://\x01\x80.com/")).to eq('http://%01%80.com/')
    end

    it 'adds a trailing slash when missing' do
      expect(WebriskHash.canonicalize('http://notrailingslash.com')).to eq('http://notrailingslash.com/')
    end

    it 'removes explicit port numbers' do
      expect(WebriskHash.canonicalize('http://www.gotaport.com:1234/')).to eq('http://www.gotaport.com/')
    end

    it 'trims surrounding spaces' do
      expect(WebriskHash.canonicalize('  http://www.google.com/  ')).to eq('http://www.google.com/')
    end

    it 'escapes leading spaces in hostname' do
      expect(WebriskHash.canonicalize('http:// leadingspace.com/')).to eq('http://%20leadingspace.com/')
    end

    it 'preserves percent-encoded leading space in hostname' do
      expect(WebriskHash.canonicalize('http://%20leadingspace.com/')).to eq('http://%20leadingspace.com/')
    end

    it 'adds http scheme when hostname starts with encoded space' do
      expect(WebriskHash.canonicalize('%20leadingspace.com/')).to eq('http://%20leadingspace.com/')
    end

    it 'preserves https scheme' do
      expect(WebriskHash.canonicalize('https://www.securesite.com/')).to eq('https://www.securesite.com/')
    end

    it 'preserves percent-escaped characters in path' do
      expect(WebriskHash.canonicalize('http://host.com/ab%23cd')).to eq('http://host.com/ab%23cd')
    end

    it 'collapses repeated slashes in path while preserving query slashes' do
      expect(WebriskHash.canonicalize('http://host.com//twoslashes?more//slashes')).to eq('http://host.com/twoslashes?more//slashes')
    end

    it 'does not hang on invalid unicode sequences' do
      expect(WebriskHash.canonicalize('https://www.sample.com/path/text%2C-Float-%26%E2%80%A8-')).to match(%r{https://www.sample.com/path/text})
    end

    it 'removes dot-segments in the path' do
      expect(WebriskHash.canonicalize('https://example.com/././foo')).to eq('https://example.com/foo')
    end

    it 'encodes spaces in path' do
      expect(WebriskHash.canonicalize('https://example.org/foo bar')).to eq('https://example.org/foo%20bar')
    end
  end
end
