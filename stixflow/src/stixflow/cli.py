"""stixflow command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.tree import Tree

from . import __version__
from .export import FORMATS
from .hunt import Hunter
from .report import attack_id, build_report
from .store import IngestResult, StixStore
from .taxii_client import TaxiiClient, TaxiiError

console = Console()


def _client(args) -> TaxiiClient:
    return TaxiiClient(
        args.server,
        username=args.user or os.environ.get("TAXII_USER"),
        password=args.password or os.environ.get("TAXII_PASSWORD"),
        verify_tls=not args.insecure,
    )


def _resolve_api_root(client: TaxiiClient, api_root: str | None) -> str:
    if api_root:
        return api_root
    disc = client.discover()
    root = disc.get("default") or (disc.get("api_roots") or [None])[0]
    if not root:
        raise TaxiiError("Server advertises no API roots; pass --api-root")
    return root


# ---------------------------------------------------------------------- commands
def cmd_serve(args) -> int:
    from .server import create_app

    app = create_app(args.data_dir, args.user, args.password)
    console.print(f"[bold green]TAXII 2.1 demo server[/] on http://{args.host}:{args.port}/taxii2/")
    app.run(host=args.host, port=args.port, debug=False)
    return 0


def cmd_discover(args) -> int:
    client = _client(args)
    disc = client.discover()
    console.print(f"[bold]{disc.get('title', 'TAXII server')}[/]  {disc.get('description', '')}")
    for root in disc.get("api_roots", []):
        tree = Tree(f"[cyan]API root[/] {root}")
        try:
            for c in client.collections(root):
                rw = ("R" if c.get("can_read") else "-") + ("W" if c.get("can_write") else "-")
                tree.add(f"[green]{c['id']}[/]  {c.get('title', '')}  [dim]({rw})[/]")
        except TaxiiError as e:
            tree.add(f"[red]{e}[/]")
        console.print(tree)
    return 0


def cmd_pull(args) -> int:
    client = _client(args)
    api_root = _resolve_api_root(client, args.api_root)
    collections = client.collections(api_root)
    targets = [c for c in collections if args.collection in (None, c["id"], c.get("title"))]
    if not targets:
        console.print(f"[red]No collection matching {args.collection!r}[/]")
        return 1

    store = StixStore(args.db)
    for coll in targets:
        feed = f"{api_root}|{coll['id']}"
        added_after = None if args.full else (args.added_after or store.get_sync(feed))
        total, last_seen = IngestResult(), None
        for page in client.iter_objects(api_root, coll["id"], added_after=added_after,
                                        page_size=args.page_size, match_type=args.type):
            total += store.ingest(page.objects, source=f"taxii:{coll.get('title', coll['id'])}")
            last_seen = page.date_added_last or last_seen
        if last_seen:
            store.set_sync(feed, last_seen)
        mode = "full" if not added_after else f"since {added_after}"
        console.print(f"[green]{coll.get('title', coll['id'])}[/] ({mode}): "
                      f"+{total.added} new, {total.updated} updated, {total.skipped} unchanged")
    return 0


def cmd_push(args) -> int:
    client = _client(args)
    api_root = _resolve_api_root(client, args.api_root)
    bundle = json.loads(Path(args.file).read_text())
    status = client.add_objects(api_root, args.collection, bundle.get("objects", []))
    console.print(f"status={status.get('status')} success={status.get('success_count')} "
                  f"failure={status.get('failure_count')}")
    return 0 if not status.get("failure_count") else 2


def cmd_import(args) -> int:
    store = StixStore(args.db)
    for f in args.files:
        res = store.ingest_bundle(json.loads(Path(f).read_text()), source=f"file:{Path(f).name}")
        console.print(f"[green]{f}[/]: +{res.added} new, {res.updated} updated, {res.skipped} unchanged")
    return 0


def cmd_stats(args) -> int:
    store = StixStore(args.db)
    table = Table(title=f"stixflow store: {args.db}")
    table.add_column("STIX type")
    table.add_column("Count", justify="right")
    for t, n in store.counts_by_type().items():
        table.add_row(t, str(n))
    table.add_row("[dim]observables (parsed IOCs)[/]", f"[dim]{len(store.observables())}[/]")
    console.print(table)
    return 0


def cmd_pivot(args) -> int:
    store = StixStore(args.db)
    starts = []
    if "--" in args.query:
        obj = store.get(args.query)
        starts = [obj] if obj else []
    if not starts:
        starts = [store.get(r["indicator_id"]) for r in store.find_by_value(args.query)]
    if not starts:
        starts = store.search(args.query)
    starts = [s for s in starts if s]
    if not starts:
        console.print(f"[yellow]Nothing found for {args.query!r}[/]")
        return 1

    for obj in starts[:5]:
        tree = Tree(f"[bold]{obj.get('name', obj['id'])}[/] [dim]{obj['type']}[/]")
        nodes: dict[str, Tree] = {obj["id"]: tree}
        for _depth, rel, direction, other, parent in store.related(obj["id"], max_depth=args.depth):
            arrow = "->" if direction == "out" else "<-"
            aid = attack_id(other)
            label = (f"{arrow} [cyan]{rel}[/] {aid + ' ' if aid else ''}"
                     f"{other.get('name', other['id'])} [dim]{other['type']}[/]")
            nodes[other["id"]] = nodes.get(parent, tree).add(label)
        console.print(tree)
    return 0


def cmd_hunt(args) -> int:
    store = StixStore(args.db)
    hunter = Hunter(store)
    all_hits = []
    for f in args.logs:
        all_hits += hunter.hunt_file(f)

    if not all_hits:
        console.print("[green]No matches.[/]")
        return 0

    table = Table(title=f"{len(all_hits)} indicator match(es)")
    for col in ("Line", "Observed", "Indicator", "Linked to"):
        table.add_column(col)
    for h in all_hits:
        table.add_row(str(h.line_no), h.observed, f"{h.indicator_name}\n[dim]{h.matched}[/]",
                      "\n".join(h.context[:4]) or "-")
    console.print(table)

    if args.report:
        Path(args.report).write_text(build_report(store, "Hunt Report", all_hits))
        console.print(f"Report written to [bold]{args.report}[/]")
    return 3 if args.fail_on_hit else 0  # non-zero lets CI / cron jobs alert


def cmd_export(args) -> int:
    store = StixStore(args.db)
    data = FORMATS[args.format](store)
    if args.output:
        Path(args.output).write_text(data)
        console.print(f"Wrote {args.format} export to [bold]{args.output}[/]")
    else:
        sys.stdout.write(data)
    return 0


def cmd_report(args) -> int:
    store = StixStore(args.db)
    md = build_report(store, args.title)
    if args.output:
        Path(args.output).write_text(md)
        console.print(f"Report written to [bold]{args.output}[/]")
    else:
        sys.stdout.write(md)
    return 0


# ---------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="stixflow", description="STIX 2.1 / TAXII 2.1 threat-intel pipeline")
    p.add_argument("--version", action="version", version=f"stixflow {__version__}")
    p.add_argument("--db", default=os.environ.get("STIXFLOW_DB", "stixflow.db"), help="SQLite store path")
    sub = p.add_subparsers(dest="command", required=True)

    def taxii_args(sp):
        sp.add_argument("server", help="TAXII server base URL, e.g. http://127.0.0.1:5000")
        sp.add_argument("--api-root", help="API root URL (default: server's advertised default)")
        sp.add_argument("--user", help="Basic auth user (or TAXII_USER env)")
        sp.add_argument("--password", help="Basic auth password (or TAXII_PASSWORD env)")
        sp.add_argument("--insecure", action="store_true", help="Skip TLS verification (lab use only)")

    sp = sub.add_parser("serve", help="Run the local demo TAXII 2.1 server")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=5000)
    sp.add_argument("--data-dir", help="Directory of STIX bundles to serve (default: bundled samples)")
    sp.add_argument("--user")
    sp.add_argument("--password")
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser("discover", help="Show API roots and collections on a TAXII server")
    taxii_args(sp)
    sp.set_defaults(func=cmd_discover)

    sp = sub.add_parser("pull", help="Pull objects from TAXII collections into the store (incremental)")
    taxii_args(sp)
    sp.add_argument("-c", "--collection", help="Collection id or title (default: all readable)")
    sp.add_argument("--added-after", help="Override incremental cursor (RFC 3339 timestamp)")
    sp.add_argument("--full", action="store_true", help="Ignore saved cursor and pull everything")
    sp.add_argument("--type", action="append", help="Only pull these STIX types (repeatable)")
    sp.add_argument("--page-size", type=int, default=100)
    sp.set_defaults(func=cmd_pull)

    sp = sub.add_parser("push", help="POST a STIX bundle to a writable TAXII collection")
    taxii_args(sp)
    sp.add_argument("-c", "--collection", required=True)
    sp.add_argument("file")
    sp.set_defaults(func=cmd_push)

    sp = sub.add_parser("import", help="Import STIX bundle file(s) into the store")
    sp.add_argument("files", nargs="+")
    sp.set_defaults(func=cmd_import)

    sp = sub.add_parser("stats", help="Show what's in the store")
    sp.set_defaults(func=cmd_stats)

    sp = sub.add_parser("pivot", help="Walk the relationship graph from an IOC, STIX id, or name")
    sp.add_argument("query")
    sp.add_argument("--depth", type=int, default=2)
    sp.set_defaults(func=cmd_pivot)

    sp = sub.add_parser("hunt", help="Match stored indicators against log files")
    sp.add_argument("logs", nargs="+")
    sp.add_argument("--report", help="Also write a Markdown hunt report")
    sp.add_argument("--fail-on-hit", action="store_true", help="Exit 3 when any indicator matches")
    sp.set_defaults(func=cmd_hunt)

    sp = sub.add_parser("export", help="Export IOCs (csv, json, txt blocklist) or a STIX bundle")
    sp.add_argument("-f", "--format", choices=sorted(FORMATS), default="csv")
    sp.add_argument("-o", "--output")
    sp.set_defaults(func=cmd_export)

    sp = sub.add_parser("report", help="Generate a Markdown intel report")
    sp.add_argument("-o", "--output")
    sp.add_argument("--title", default="Threat Intelligence Summary")
    sp.set_defaults(func=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except TaxiiError as e:
        console.print(f"[red]TAXII error:[/] {e}")
        return 1
    except (OSError, ValueError) as e:
        console.print(f"[red]Error:[/] {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
