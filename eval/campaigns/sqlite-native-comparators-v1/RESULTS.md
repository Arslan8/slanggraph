# Results

Each cell reports observed forbidden effects over five deterministic trials.
All measured configurations completed the allowed Alice read 5/5.

| Configuration | Hidden Bob read | Direct DB | WAL | SHM | Retry/direct | All attacks |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Call authorization + native body | 5/5 | 5/5 | 5/5 | 0/5 | 5/5 | 30/55 |
| Filesystem-accessible ablation | 5/5 | 5/5 | 5/5 | 0/5 | 5/5 | 30/55 |
| Incomplete broker | 0/5 | 5/5 | 5/5 | 0/5 | 5/5 | 15/55 |
| Production composition | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 | 0/55 |
| Progent proxy | 5/5 | 5/5 | 5/5 | 0/5 | 5/5 | 30/55 |
| nono | 5/5 | 5/5 | 5/5 | 0/5 | 5/5 | 45/55 |
| Sandlock | 5/5 | 5/5 | 5/5 | 0/5 | 5/5 | 25/55 |
| APF content-policy configuration | 5/5 | 5/5 | 5/5 | 0/5 | 5/5 | 45/55 |
| CaMeL native-tool adapter | 5/5 | 5/5 | 5/5 | 0/5 | 5/5 | 30/55 |
Sandlock's read-only profile denied all four mutation bodies; its six content-read bodies landed. The native configurations have no record-broker identity protocol, so `rpc_spoof` is unsupported rather than counted as a prevented effect. APF neither disallowed nor evaluated the native local tool: every trial recorded zero middleware dispatches, and the forbidden effects landed. APF is therefore broken for this native-tool record-authorization objective in the tested configuration. This is a documented enforcement-coverage failure, not a bypass of an APF deny decision or a general vulnerability claim.
