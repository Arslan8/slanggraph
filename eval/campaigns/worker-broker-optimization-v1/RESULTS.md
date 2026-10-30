# Worker and broker optimization route costs

Five fresh sessions, ten warmups, and 20 measured calls per session were used for each route. The table reports Student-t intervals over session means. Preflight/setup is excluded; all recurring per-call enforcement is included.

| Route | First use ms [95% CI] | Reused ms [95% CI] | Added ms vs matching direct baseline | Change from prior aggressive run |
|---|---:|---:|---:|---:|
| language | 61.18 [54.82, 67.55] | 11.78 [11.48, 12.08] | 11.74 [11.44, 12.03] | +0.1% (ratio CI 0.979-1.023) |
| landlock-aggressive | 525.88 [504.52, 547.24] | 476.88 [475.61, 478.14] | 476.83 [475.57, 478.09] | +2.2% (ratio CI 1.014-1.030) |
| container | 1619.94 [1148.51, 2091.37] | 148.57 [147.90, 149.24] | 148.52 [147.85, 149.19] | +0.2% (ratio CI 0.997-1.007) |
| broker | 180.65 [167.47, 193.82] | 143.51 [140.38, 146.65] | 143.40 [140.26, 146.53] | +1.9% (ratio CI 1.005-1.033) |

Before/after intervals use an independent-session bootstrap of the ratio of means (100,000 resamples; seed 20261029). Because the campaigns were sequential, small differences may include host drift.
