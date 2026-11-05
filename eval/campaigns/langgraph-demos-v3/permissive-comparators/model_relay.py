"""Relay a sandbox-local Ollama port to the host benchmark service."""

from __future__ import annotations

import argparse
import contextlib
import socket
import threading


def copy_stream(
    source: socket.socket,
    destination: socket.socket,
    replacement: tuple[bytes, bytes] | None = None,
) -> None:
    try:
        while chunk := source.recv(64 * 1024):
            if replacement is not None:
                chunk = chunk.replace(*replacement)
            destination.sendall(chunk)
    finally:
        with contextlib.suppress(OSError):
            destination.shutdown(socket.SHUT_WR)


def relay(
    client: socket.socket,
    target: tuple[str, int],
    replacement: tuple[bytes, bytes] | None,
) -> None:
    with client, socket.create_connection(target) as upstream:
        outgoing = threading.Thread(
            target=copy_stream,
            args=(client, upstream, replacement),
        )
        incoming = threading.Thread(target=copy_stream, args=(upstream, client))
        outgoing.start()
        incoming.start()
        outgoing.join()
        incoming.join()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=11434)
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument(
        "--rewrite-authority",
        nargs=2,
        metavar=("FROM", "TO"),
        help="Rewrite the HTTP authority while crossing a named policy endpoint.",
    )
    args = parser.parse_args()
    target = (args.target_host, args.target_port)
    replacement = (
        tuple(value.encode() for value in args.rewrite_authority)
        if args.rewrite_authority is not None
        else None
    )
    with socket.create_server((args.listen_host, args.listen_port)) as server:
        while True:
            client, _ = server.accept()
            threading.Thread(
                target=relay,
                args=(client, target, replacement),
                daemon=True,
            ).start()


if __name__ == "__main__":
    main()
