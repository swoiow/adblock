# adblock
coredns plugin to block domains.


## Usage

```
.:1053 {
    bind 127.0.0.1

    adblock {
        black-list <AbsolutePath>/list.txt
        black-list https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/reject-list.txt
    }

    forward . 223.5.5.5:53
    log . {
        class all
    }

    errors
}
```

## Feature

- 支持从Http加载域名

## TODO

- Github Action 创建缓存文件
- 使用缓存文件
- 增加response的报文类型
- Cache最近的查询
- expose过滤器的参数
- 
