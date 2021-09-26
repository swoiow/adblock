# blocked

This branch is for record rules.

## Commands

```
export fn="sublime.txt"
sort $fn|uniq > $fn"2" && mv $fn"2" $fn
```

```
export fn="default.txt"
sort $fn tencent.txt tencent.txt|uniq -u > $fn"2" && mv $fn"2" $fn
```