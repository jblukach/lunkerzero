# lunkerzero

## AWS Chatbot for Slack

### Add Artifact

```
@aws invoke walleye --payload {"add”: “4n6ir.com”}
```

```
@aws invoke walleye --payload {"add”: “127.0.0.1”}
```

```
@aws invoke walleye --payload {"add”: “::1”}
```

### List Artifacts

```
@aws invoke walleye --payload {"list”: “all”}
```

```
@aws invoke walleye --payload {"list”: “dns”}
```

```
@aws invoke walleye --payload {"list”: “ipv4”}
```

```
@aws invoke walleye --payload {"list”: “ipv6”}
```

### Remove Artifact

```
@aws invoke walleye --payload {"remove”: “4n6ir.com”}
```

```
@aws invoke walleye --payload {"remove”: “127.0.0.1”}
```

```
@aws invoke walleye --payload {"remove”: “::1”}
```

### Delete Artifacts

```
@aws invoke walleye --payload {"delete”: “all”}
```

```
@aws invoke walleye --payload {"delete”: “dns”}
```

```
@aws invoke walleye --payload {"delete”: “ipv4”}
```

```
@aws invoke walleye --payload {"delete”: “ipv6”}
```

### Autonomous System

```
@aws invoke walleye --payload {"as”:”AS65535”}
```

```
@aws invoke walleye --payload {"list”: “as”}
```

```
@aws invoke walleye --payload {"delete”: “as”}
```

![Lunker Zero (LZ)](images/lunkerzero.png)
