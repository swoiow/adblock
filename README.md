# adblock

A coredns plugin to block domains.

## Usage

```
.:1053 {
    bind 127.0.0.1

    adblock {
        # bloom filter capacity & rate. default: 250_000 0.0001
        size_rate 250_000 0.0001
    
        # enable log, remove is disable
        log
        
        # blocked_query_response, soa is default. Options: soa / zero / hinfo / no-ans
        resp_type zero
        
        # (the last cache-data will be ues) load cache file from local or remote
        cache_data https://example.com/rules.data
        cache_data <AbsolutePath>/rules.data
        
        # black list to block query, load rules from local or remote
        black_list <AbsolutePath>/list.txt
        black_list https://example.com/reject-list.txt
        
        # white list to disable block
        white_list <AbsolutePath>/white-list.txt
        white_list https://example.com/white-list.txt
    }

    forward . 223.5.5.5:53
    log . {
        class all
    }

    errors
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

## TODO

- [ ] Github Action 创建缓存文件
- [x] 使用缓存文件
- [x] 增加response的报文类型
- [ ] Cache最近的查询
- [x] expose过滤器的参数
- [x] 增加white_list
- [ ] 
