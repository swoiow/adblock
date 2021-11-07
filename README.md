# blocked 
[![TEST](https://github.com/swoiow/blocked/actions/workflows/test.yml/badge.svg)](https://github.com/swoiow/blocked/actions/workflows/test.yml)
[![RELEASE](https://github.com/swoiow/blocked/actions/workflows/dist.yml/badge.svg)](https://github.com/swoiow/blocked/actions/workflows/dist.yml)

A coredns plugin to block domains/query.

## Usage

```
.:1053 {
    errors
    bind 127.0.0.1
    forward . 223.5.5.5:53

    log . {
        class all
    }

    blocked {
        # bloom filter capacity & rate. default: 250_000 0.001
        size_rate 250_000 0.001
    
        # enable log, remove is disable
        log
        
        # hostname query, default: refused. Options: ignore / refused
        hostname_query refused
        
        # blocked_query_response, default: soa. Options: soa / zero / hinfo / no-ans / refused
        #  can config some special for qtypes
        resp_type zero {
            refused ANY AAAA HTTPS MX PTR SRV CNAME
            zero AAAA
        }
        
        # covert domain in wildcard, and compare all to filter
        #  if use it black_list must used `local+` prefix to skip domain valid
        wildcard
        
        # (the last cache-data will be ues) load cache file from local or remote
        cache_data https://example.com/rules.data
        cache_data <AbsolutePath>/rules.data
        
        # black list to block query, load rules from local or remote.
        #  use `local+` will skip the domain verify means allow any line exclude comment
        black_list <AbsolutePath>/list.txt
        black_list local+<AbsolutePath>/list.txt
        black_list https://example.com/reject-list.txt
        
        # white list to disable block
        white_list <AbsolutePath>/white-list.txt
        white_list https://example.com/white-list.txt
    }
}
```

## Feature

- 大规则小内存匹配快，Thanks: [bits-and-blooms](https://github.com/bits-and-blooms/bloom)
- 支持从远端/本地加载缓存

+ 支持黑/白名单的规则，并可从远端/本地加载规则
  - 默认远端加载会检查域名合法性；本地使用`local+`前缀，跳过合法性检查
+ 支持多种屏蔽的返回报文
  - `SOA`
  - `HINFO`
  - `ZERO`
  - `No-Ans`
  - `NX` - `NXDOMAIN`
  - `REFUSED`
+ 支持屏蔽指定查询类型
  - [list of dns record types](https://en.wikipedia.org/wiki/List_of_DNS_record_types)
+ 支持多种格式的规则文件
  - `hosts` - `HostParser`
  - `surge` - `SurgeParser`
  - `dnsmasq` - `DnsmasqParser`
  - `domain` - `DomainParser`
  - `abnf` - `ABNFParser`, 需要使用`abnf+`前缀指定解析器

## TODO

- [x] Github Action 创建缓存文件
- [x] Github Action 创建bin文件
- [x] 使用缓存文件
- [x] 增加response的报文类型
- [x] expose过滤器的参数
- [x] 增加white_list
- [x] 屏蔽指定类型的dns查询
- [x] 支持泛域名屏蔽规则(需要考虑n级域名的问题)
- [ ] 引入AdGuard的过滤器
- [ ] ...

## Changelog & Note

- [Wiki](https://github.com/swoiow/blocked/wiki/Changelog-&-Note)
