# INIT command
This command establishes a shared key to be used to exchange messages between addresses

## PARAMS
| Name          | Type   | Description                               |
| --------------| ------ | ----------------------------------------- |
| `VERSION`     | String | Broadcast Format Version                  |
| `DESTINATION` | String | Address of the message recipient          |
| `SHARED_KEY`  | String | Shared key to be used to decrypt messages |

## Formats

### Version `0`
- `VERSION|DESTINATION|SHARED_KEY`

## Examples
```
cm:INIT|0|1JDogZS6tQcSxwfxhv6XKKjcyicYA4Feev|SHARED_KEY_GOES_HERE
This example establishes a shared key to securely exchange messages with address 1JDogZS6tQcSxwfxhv6XKKjcyicYA4Feev
```
## Rules

## Notes
- `INIT` command may only be used if `DESTINATION` public key is known
- `SHARED_KEY` is a shared key which should only be decrypted/known by sender and receiver