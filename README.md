# adblock [![RELEASE](https://github.com/swoiow/adblock/actions/workflows/build-bin.yml/badge.svg)](https://github.com/swoiow/adblock/actions/workflows/build-bin.yml)

A coredns plugin to block domains.

## Usage

```
.:1053 {
    errors
    bind 127.0.0.1
    forward . 223.5.5.5:53

    log . {
        class all
    }

    adblock {
        # bloom filter capacity & rate. default: 300_000 0.01
        size_rate 300_000 0.01
    
        # enable log, remove is disable
        log
        
        # block_query_type, return REFUSED
        block_qtype A AAAA HTTPS MX PTR SRV CNAME
        
        # blocked_query_response, soa is default. Options: soa / zero / hinfo / no-ans
        resp_type zero
        
        # (the last cache-data will be ues) load cache file from local or remote
        cache_data https://example.com/rules.data
        cache_data <AbsolutePath>/rules.data
        
        # black list to block query, load rules from local or remote.
        # use local+ will disable the domain means allow any line exclude comment
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

- 支持从远端/本地加载规则
- 支持从远端/本地加载缓存
+ 支持多种屏蔽的返回报文
  - `SOA`
  - `HINFO`
  - `ZERO`
  - `No-Ans`
  - `NX`
  - `REFUSED`
+ 支持屏蔽指定类型查询
  - [List_of_DNS_record_types](https://en.wikipedia.org/wiki/List_of_DNS_record_types)
+ 支持多种格式的规则文件
  - `hosts` - `HostParser`
  - `surge` - `SurgeParser`
  - `dnsmasq` - `DnsmasqParser`
  - `domain` - `DomainParser`

## TODO

- [x] Github Action 创建缓存文件
- [x] Github Action 创建bin文件
- [x] 使用缓存文件
- [x] 增加response的报文类型
- [ ] Cache最近的查询
- [x] expose过滤器的参数
- [x] 增加white_list
- [x] 屏蔽指定类型的dns查询
- [ ] 引入AdGuard的过滤器
- [ ] 支持泛域名(需要考虑n级域名的问题)
- [ ]
