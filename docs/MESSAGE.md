# MESSAGE command
This command sends a message to the `DESTINATION` address.

## PARAMS
| Name                | Type   | Description                                          |
| ------------------- | ------ | ---------------------------------------------------- |
| `VERSION`           | String | Broadcast Format Version                             |
| `ADDRESS`           | String | Address of the message recipient                     |
| `PLAINTEXT_MESSAGE` | String | Plaintext message (visible to all!)                  |
| `ENCRYPTED_MESSAGE` | String | Message encryted with shared key from `INIT` command |

## Formats

### Version `0`
- `VERSION|ADDRESS|PLAINTEXT_MESSAGE`

### Version `1`
- `VERSION|ADDRESS|ENCRYPTED_MESSAGE`

## Examples
```
cm:MSG|0|1JDogZS6tQcSxwfxhv6XKKjcyicYA4Feev|Hello
This example send a plaintext message to 1JDogZS6tQcSxwfxhv6XKKjcyicYA4Feev
```

```
cm:MSG|1|1JDogZS6tQcSxwfxhv6XKKjcyicYA4Feev|ENCRYPTED_MESSAGE_GOES_HERE
This example send an encrypted message to 1JDogZS6tQcSxwfxhv6XKKjcyicYA4Feev
```

## Rules

## Notes
- `MSG` can be used in lie of `MESSAGE` to save on data encoding costs