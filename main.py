"""NekoCTI CLI.

    uv run python main.py ingest             # poll all sources once
    uv run python main.py digest             # build a grouped digest, write it to today's vault daily note
    uv run python main.py digest --no-write  # same, print only, don't touch the vault
    uv run python main.py archive --limit 20 # raw recent-entries listing
    uv run python main.py classify           # run real ATT&CK classification on unclassified articles
    uv run python main.py classify-pocs      # tag CVEs with real PoC evidence against MITRE ATT&CK
    uv run python main.py enrich             # NVD severity, EPSS, CISA KEV, and in-the-wild reporting
    uv run python main.py enrich --limit 500 # same, allowing more (rate-limited) NVD lookups this run
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import db
import digest as digest_mod
import ingest

# Windows' console defaults to cp1252, which can't encode real characters
# that show up in scraped article titles (emoji, smart quotes, etc.) --
# the same UnicodeEncodeError class already hit elsewhere in this
# ecosystem. Reconfigure to UTF-8 up front rather than catching it per print.
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


def cmd_ingest(_args: argparse.Namespace) -> None:
    results = ingest.run_all()
    for r in results:
        if r.get("error"):
            print(f"[{r['source']}] FAILED: {r['error']}")
            continue
        print(f"[{r['source']}] seen={r['seen']} new={r['new']} "
              f"high_ticket={r['high_ticket']} skipped_304={r['skipped_304']}")


def cmd_digest(args: argparse.Namespace) -> None:
    db.init_db()
    conn = db.connect()
    try:
        text = digest_mod.build_digest(conn, since_hours=args.hours)
    finally:
        conn.close()

    print(text)

    if not args.no_write:
        wrote = digest_mod.write_to_daily_note(text)
        if wrote:
            print(f"\n(written to today's vault daily note)")
        else:
            print(f"\n(today's vault daily note doesn't exist yet -- not written)")


def cmd_archive(args: argparse.Namespace) -> None:
    db.init_db()
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT id, title, link, published_at, high_ticket FROM articles "
            "ORDER BY published_at DESC LIMIT ?",
            (args.limit,),
        ).fetchall()

        if not rows:
            print("Nothing in the archive yet -- run `ingest` first.")
            return

        for row in rows:
            marker = "[HIGH TICKET] " if row["high_ticket"] else ""
            print(f"{marker}{row['title']}")
            print(f"  {row['link']}")

            vendors = conn.execute(
                "SELECT DISTINCT vendor_term FROM vendor_matches WHERE article_id = ?",
                (row["id"],),
            ).fetchall()
            if vendors:
                print(f"  vendors: {', '.join(v['vendor_term'] for v in vendors)}")

            entities = conn.execute(
                "SELECT DISTINCT entity_name FROM entity_matches WHERE article_id = ?",
                (row["id"],),
            ).fetchall()
            if entities:
                print(f"  tracked entities: {', '.join(e['entity_name'] for e in entities)}")

            cves = conn.execute(
                "SELECT cve_id, cvss_score FROM cve_mentions WHERE article_id = ?",
                (row["id"],),
            ).fetchall()
            if cves:
                cve_strs = [f"{c['cve_id']} ({c['cvss_score']})" if c["cvss_score"] else c["cve_id"]
                            for c in cves]
                print(f"  CVEs: {', '.join(cve_strs)}")
            print()
    finally:
        conn.close()


def cmd_enrich(args: argparse.Namespace) -> None:
    import enrich
    import extract

    db.init_db()
    conn = db.connect()
    try:
        if not args.no_backfill:
            stats = db.backfill_exploited_in_wild(conn, extract.exploitation_evidence)
            print(f"In-the-wild reporting:    {stats['cve_reports']} claim(s) across "
                  f"{stats['distinct_cves']} CVE(s), {stats['articles_changed']} article flag(s) changed")

        summary = enrich.enrich(
            conn,
            nvd_limit=args.limit,
            do_nvd=not args.no_nvd,
            do_epss=not args.no_epss,
            do_kev=not args.no_kev,
        )
        print(f"EPSS scores updated:      {summary['epss_updated']}")
        print(f"CVEs listed in CISA KEV:  {summary['kev_listed']}"
              + ("  (catalog fetch failed)" if summary.get("kev_failed") else ""))
        print(f"NVD lookups:              {summary['nvd_checked']} checked, "
              f"{summary['nvd_scored']} with a score, {summary['nvd_failed']} failed"
              f"{'' if summary['nvd_key'] else '  (no API key: 5 requests/30s)'}")
        print(f"Promoted to high ticket:  {summary['promoted_high_ticket']}")
    finally:
        conn.close()


def cmd_classify(args: argparse.Namespace) -> None:
    import attack

    db.init_db()
    conn = db.connect()
    try:
        rows = db.articles_needing_attack_classification(conn, args.limit)
        if not rows:
            print("Nothing to classify -- every article already has a real classification run.")
            return

        async def run():
            for i, row in enumerate(rows, start=1):
                body = row["full_text"] or row["description"] or ""
                techniques = await attack.classify_article(row["title"], body)
                db.insert_attack_techniques(conn, row["id"], techniques)
                names = ", ".join(t[0] for t in techniques) if techniques else "(none identified)"
                print(f"[{i}/{len(rows)}] {row['title'][:70]} -> {names}")

        asyncio.run(run())
    finally:
        conn.close()


def cmd_classify_pocs(args: argparse.Namespace) -> None:
    import cve_attack

    db.init_db()
    conn = db.connect()
    try:
        applied = cve_attack.apply_expert_mappings(conn)
        print(f"Expert (MITRE CTID) mappings applied to {applied} real CVE(s).")

        cve_ids = db.cves_needing_llm_attack_classification(conn, args.limit)
        if not cve_ids:
            print("No further real PoC-evidence CVEs need LLM classification.")
            return

        async def run():
            for i, cve_id in enumerate(cve_ids, start=1):
                title = db.get_cve_title(conn, cve_id) or cve_id
                techniques = await cve_attack.classify_cve_llm(cve_id, title)
                rows = [(tid, name, "llm", None, None, None) for tid, name in techniques]
                if rows:
                    db.insert_cve_attack_techniques(conn, cve_id, rows)
                db.mark_cve_attack_checked(conn, cve_id)
                names = ", ".join(t[0] for t in techniques) if techniques else "(none identified)"
                print(f"[{i}/{len(cve_ids)}] {cve_id} -> {names}")

        asyncio.run(run())
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(prog="nekocti")
    sub = parser.add_subparsers(dest="command", required=True)

    p_ingest = sub.add_parser("ingest", help="poll all sources once")
    p_ingest.set_defaults(func=cmd_ingest)

    p_digest = sub.add_parser("digest", help="build a grouped digest, write it to the vault")
    p_digest.add_argument("--hours", type=int, default=24,
                           help="how far back to include (default: 24)")
    p_digest.add_argument("--no-write", action="store_true",
                           help="print only, don't write to the vault daily note")
    p_digest.set_defaults(func=cmd_digest)

    p_archive = sub.add_parser("archive", help="raw recent-entries listing")
    p_archive.add_argument("--limit", type=int, default=20)
    p_archive.set_defaults(func=cmd_archive)

    p_classify = sub.add_parser("classify", help="real ATT&CK classification on unclassified articles")
    p_classify.add_argument("--limit", type=int, default=20,
                             help="max articles to classify this run (default: 20, local inference is slow)")
    p_classify.set_defaults(func=cmd_classify)

    p_classify_pocs = sub.add_parser("classify-pocs", help="tag CVEs with real PoC evidence against MITRE ATT&CK")
    p_classify_pocs.add_argument("--limit", type=int, default=50,
                                  help="max CVEs to run the LLM tier against this run (default: 50)")
    p_classify_pocs.set_defaults(func=cmd_classify_pocs)

    p_enrich = sub.add_parser("enrich", help="NVD severity, EPSS, CISA KEV and in-the-wild reporting")
    p_enrich.add_argument("--limit", type=int, default=200,
                           help="max NVD lookups this run (default: 200; NVD allows 5 requests/30s "
                                "without an API key, 50 with NVD_API_KEY set)")
    p_enrich.add_argument("--no-nvd", action="store_true", help="skip the NVD severity lookups")
    p_enrich.add_argument("--no-epss", action="store_true", help="skip the EPSS refresh")
    p_enrich.add_argument("--no-kev", action="store_true", help="skip the CISA KEV catalog check")
    p_enrich.add_argument("--no-backfill", action="store_true",
                           help="skip re-scanning stored articles for in-the-wild exploitation reporting")
    p_enrich.set_defaults(func=cmd_enrich)

    args = parser.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
