# frozen_string_literal: true

require 'spec_helper'

RSpec.describe WebriskHash::Suffixes do
  describe '.suffix_postfix_expressions' do
    it 'returns correct set for a simple host/path' do
      res = WebriskHash.suffix_postfix_expressions('http://a.b.c/1/2.html?param=1')
      expect(res).to be_a(Set)
      expect(res).to include('a.b.c/1/2.html?param=1')
      expect(res).to include('a.b.c/1/2.html')
      expect(res).to include('a.b.c/')
      expect(res).to include('a.b.c/1/')
      expect(res).to include('b.c/1/2.html?param=1')
      expect(res).to include('b.c/1/2.html')
      expect(res).to include('b.c/')
      expect(res).to include('b.c/1/')
    end

    it 'returns empty set for nil input' do
      expect(WebriskHash.suffix_postfix_expressions(nil)).to eq(Set.new)
    end

    it 'does not crash on IPv6 hosts and returns a Set' do
      res = WebriskHash.suffix_postfix_expressions('http://[::1]/1')
      expect(res).to be_a(Set)
    end

    context 'additional cases' do
      it 'generates path components for IP addresses' do
        res = WebriskHash.suffix_postfix_expressions('http://192.168.0.1/1')
        expect(res).to eq(Set.new(['192.168.0.1/1', '192.168.0.1/']))
      end

      it 'handles long path components' do
        res = WebriskHash.suffix_postfix_expressions('http://a.b.c/1/2/3/4/5/6/7/8.html?param=1')
        expect(res).to include('a.b.c/1/2/3/4/')
        expect(res).to include('a.b.c/1/2/')
        expect(res).to include('b.c/1/2/3/4/5/6/7/8.html?param=1')
      end

      it 'handles six-level subdomain' do
        res = WebriskHash.suffix_postfix_expressions('http://a.b.c.d.e.f.g/1.html')
        expect(res).to include('a.b.c.d.e.f.g/1.html')
        expect(res).to include('a.b.c.d.e.f.g/')
        expect(res).to include('c.d.e.f.g/1.html')
        expect(res).to include('c.d.e.f.g/')
        expect(res).to include('d.e.f.g/1.html')
        expect(res).to include('d.e.f.g/')
        expect(res).to include('e.f.g/1.html')
        expect(res).to include('e.f.g/')
        expect(res).to include('f.g/1.html')
        expect(res).to include('f.g/')
      end

      it 'handles seven-level subdomain' do
        res = WebriskHash.suffix_postfix_expressions('http://x.a.b.c.d.e.f.g/1.html')
        expect(res).to include('x.a.b.c.d.e.f.g/1.html')
        expect(res).to include('c.d.e.f.g/1.html')
        expect(res).to include('f.g/')
      end
    end
  end
end
