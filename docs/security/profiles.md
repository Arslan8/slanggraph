# slangGraph profile grammar

Profile files use the `.slp` suffix. They describe constructive discretionary
authority: a tool says what a call needs or wants, and a principal says which
resources they may use or share. Evaluation computes:

`tool profile with bound arguments ∩ principal envelope ∩ inbound shares`

This result is a `ConstructiveGrant`. It is not the kernel-facing `Grant` from
ADR 0007; mandatory policy still filters it before backend lowering.

## Complete example

```text
tool read_file {
  owner analyst
  grant analyst manager: call
  requires fs:read
  runs inprocess
  delegable no
  syscalls @file-read
  fs read ${path} need
  net none
  exec none
  service none
  limits cpu 2s mem 256M pids 1 nofile 64 wall 5s
  returns sensitive
}

principal alice {
  roles analyst
  scopes fs:read
  fs ${home}/**
  net connect 443
  exec none
  service mail(as: alice@corp.example)
  credential gmail(scope: send)
  share bob: read ${home}/shared/**
}
```

Statements end at a newline or semicolon. A `#` starts a comment outside a
quoted string. Each directive may occur at most once in a block. Commas divide
multiple rules in `fs`, `net`, `exec`, `service`, `credential`, and `share`.

## Frozen syntax

A tool block accepts these directives:

| Directive | Form | Default |
| --- | --- | --- |
| `owner` | `owner NAME` | required |
| `grant` | `grant SUBJECT...: call` | nobody |
| `requires` | `requires SCOPE...` | none |
| `runs` | `runs NAME` | `inprocess` |
| `delegable` | `delegable yes\|no` | `no` |
| `syscalls` | `syscalls @SET...` | `@minimal` |
| `fs` | `fs OPERATIONS PATH need\|want, ...` | `none` |
| `net` | `net connect\|bind PORT need\|want, ...` | `none` |
| `exec` | `exec PATH need\|want, ...` | `none` |
| `service` | `service KIND(KEY: VALUE, ...) need\|want, ...` | `none` |
| `limits` | `limits cpu DURATION mem SIZE pids N nofile N wall DURATION` | unset |
| `returns` | `returns NAME` | `normal` |

A principal block accepts `roles`, `scopes`, `fs`, `net`, `exec`, `service`,
`credential`, and `share`. Principal resource rules omit `need` or `want`.
Filesystem operations are `read`, `write`, `create`, `delete`, `exec`, and
`truncate`, joined with `+`. Omitting operations from a principal `fs` rule
means all six operations. A share has the form
`share SUBJECT: OPERATIONS PATH` and currently shares filesystem authority.

Durations use `ms`, `s`, or `m`. Memory uses bytes or the binary multipliers
`K`, `M`, `G`, `KB`, `MB`, `GB`, `KiB`, `MiB`, or `GiB`.

## Binding and paths

`${name}` variables are replaced from normalized arguments or explicitly
provided principal bindings. Every referenced variable must exist. Bound
filesystem and executable paths must already be canonical absolute POSIX paths:
relative paths, trailing slashes, `.` and `..` segments, NULs, and control
characters are rejected. Evaluation does not call `realpath` and does not
silently normalize a string.

The only path pattern is a terminal `/**`, meaning the named path and every
descendant. General glob characters are invalid. Intersections therefore have
an exact result: exact with exact, exact within subtree, or the narrower of two
nested subtrees.

## Evaluation rules

The caller must match a user or role in `grant` and hold every scope in
`requires`. Each tool resource line is then intersected with the principal's
own envelope and any shares addressed to the caller or one of their roles.

If a `need` line has no surviving intersection, the complete call is denied. A
removed `want` line is recorded and the call may continue. Every removal keeps
its source location and reason. Full entries supplied through
`DacOverrides(profiles=...)` replace the corresponding tool block wholesale;
they do not merge individual lines.

Construction is monotone in each authority input: removing a tool request,
principal envelope line, or share cannot add a surviving resource line.

