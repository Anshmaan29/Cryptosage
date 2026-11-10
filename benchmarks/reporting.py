"""Export measured rows and self-contained research reports; no synthetic data."""

from __future__ import annotations
import csv
import html
import json
import os
import zipfile
from pathlib import Path

CHARTS = (
    "kem-latency",
    "handshake-distribution",
    "resources",
    "bandwidth",
    "message-rekey",
    "network-delay",
)
EXPORT_FILES = (
    "results.json",
    "trials.csv",
    "report.html",
    "report.zip",
    *(f"{name}.{extension}" for name in CHARTS for extension in ("png", "svg")),
)
COLORS = ("#245641", "#a56f36")


def write_report(report, output_dir: Path):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    # Only remove generated report names, so an unavailable rerun cannot export stale plots.
    for name in EXPORT_FILES:
        (output_dir / name).unlink(missing_ok=True)
    (output_dir / "results.json").write_text(
        json.dumps(report, indent=2, allow_nan=False) + "\n"
    )
    rows = [
        {"algorithm": result["name"], **trial}
        for result in report["algorithms"]
        for trial in result.get("raw_trials", [])
    ]
    columns = ["algorithm", "trial"] + sorted(
        {key for row in rows for key in row} - {"algorithm", "trial"}
    )
    with (output_dir / "trials.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    _plots(report, output_dir)
    _html(report, output_dir)
    with zipfile.ZipFile(
        output_dir / "report.zip", "w", zipfile.ZIP_DEFLATED
    ) as bundle:
        for name in EXPORT_FILES:
            if name != "report.zip" and (output_dir / name).is_file():
                bundle.write(output_dir / name, arcname=name)


def _plots(report, output_dir):
    os.environ.setdefault(
        "MPLCONFIGDIR", str(output_dir.resolve() / ".matplotlib-cache")
    )
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import pandas as pd

    rows = [result for result in report["algorithms"] if result["status"] == "measured"]
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.titleweight": "bold",
            "figure.facecolor": "#fbfbf8",
            "axes.facecolor": "#fbfbf8",
            "text.color": "#1c352b",
            "axes.labelcolor": "#334c42",
            "axes.edgecolor": "#b9c4bb",
            "svg.hashsalt": "crytosage-benchmarks-v2",
        }
    )

    def finish(fig, name):
        fig.savefig(output_dir / (name + ".png"), dpi=160)
        fig.savefig(output_dir / (name + ".svg"))
        plt.close(fig)

    def unavailable(ax, message="Measurement not run"):
        ax.text(0.5, 0.5, message, ha="center", va="center", transform=ax.transAxes)
        ax.set_xticks([])
        ax.set_yticks([])

    def bars(ax, metrics, labels, ylabel, title, scale=1):
        frame = pd.DataFrame(
            {
                row["name"]: {
                    label: row["statistics"][metric]["mean"] / scale
                    for metric, label in zip(metrics, labels)
                    if metric in row["statistics"]
                }
                for row in rows
            }
        )
        if frame.empty:
            unavailable(ax)
        else:
            frame.plot.bar(ax=ax, color=COLORS, rot=0, width=0.7)
            ax.legend(title="Actual liboqs identifier")
        ax.set_ylabel(ylabel)
        ax.set_title(title)
        ax.grid(axis="y", alpha=0.15)
        ax.set_axisbelow(True)

    fig, ax = plt.subplots(figsize=(10, 4.8), layout="constrained")
    bars(
        ax,
        ["keygen_ms", "encapsulate_ms", "decapsulate_ms"],
        ["Key generation", "Encapsulation", "Decapsulation"],
        "Mean latency (ms)",
        f"Level-3 KEM computation · {report['metadata']['trials']} trials",
    )
    finish(fig, "kem-latency")

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.8), layout="constrained")
    for ax, metric, title in zip(
        axes,
        ["handshake_ms", "network_handshake_ms"],
        [
            "Authenticated handshake: computation",
            "Authenticated handshake: loopback + computation",
        ],
    ):
        present = [row for row in rows if metric in row["statistics"]]
        if present:
            for index, row in enumerate(present):
                samples = [trial[metric] for trial in row["raw_trials"]]
                ax.hist(
                    samples,
                    bins=min(20, max(2, len(samples) // 3)),
                    label=row["name"],
                    color=COLORS[index],
                    alpha=0.7,
                )
                ax.axvline(
                    row["statistics"][metric]["p95"],
                    color=COLORS[index],
                    linestyle="--",
                    linewidth=1.5,
                )
            ax.legend(fontsize=8)
            ax.set_xlabel("Latency (ms); dashed = nearest-rank P95")
            ax.set_ylabel("Observed trial count")
        else:
            unavailable(ax, "Full protocol callback not supplied")
        ax.set_title(title, fontsize=11)
    finish(fig, "handshake-distribution")

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.8), layout="constrained")
    bars(
        axes[0],
        ["cpu_ms"],
        ["KEM process CPU"],
        "Mean CPU time (ms)",
        "KEM CPU consumption",
    )
    bars(
        axes[1],
        ["peak_rss_bytes", "python_peak_bytes"],
        ["Sampled RSS", "Python allocation peak"],
        "MiB",
        "Memory observations (not per-KEM native peaks)",
        1024**2,
    )
    finish(fig, "resources")

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.8), layout="constrained")
    if rows:
        frame = pd.DataFrame(
            {
                row["name"]: {
                    "Public key": row["public_key_bytes"],
                    "KEM ciphertext": row["ciphertext_bytes"],
                }
                for row in rows
            }
        )
        frame.plot.bar(ax=axes[0], color=COLORS, rot=0)
    else:
        unavailable(axes[0])
    axes[0].set_ylabel("Bytes")
    axes[0].set_title("Selected KEM wire objects")
    bars(
        axes[1],
        ["handshake_bytes"],
        ["All four protocol flights"],
        "Serialized JSON bytes",
        "Whole authenticated handshake bandwidth",
    )
    finish(fig, "bandwidth")

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.8), layout="constrained")
    bars(
        axes[0],
        ["encrypt_ms", "decrypt_ms"],
        ["Encryption", "Decryption"],
        "Mean latency (ms)",
        "Message AEAD + ratchet computation",
    )
    bars(
        axes[1],
        ["rekey_ms", "network_rekey_ms"],
        ["Computation", "Loopback + computation"],
        "Mean latency (ms)",
        "Fresh authenticated session / re-key",
    )
    finish(fig, "message-rekey")

    fig, ax = plt.subplots(figsize=(11, 4.8), layout="constrained")
    delay = report["metadata"].get("configuration", {}).get("injected_send_delay_ms", 0)
    bars(
        ax,
        [
            "network_handshake_ms",
            "network_message_roundtrip_ms",
            "relay_transport_roundtrip_ms",
        ],
        [
            "Full handshake (4 sends)",
            "Message roundtrip (2 sends)",
            "Opaque roundtrip (2 sends)",
        ],
        "Mean measured latency (ms)",
        f"Actual loopback exchanges · artificial endpoint delay {delay:g} ms per send",
    )
    finish(fig, "network-delay")


def _html(report, output_dir):
    def escape(value):
        return html.escape(str(value), quote=True)

    metadata = report["metadata"]
    cards = "".join(f"<li>{escape(value)}</li>" for value in report.get("findings", []))
    stats = []
    for result in report["algorithms"]:
        if result["status"] != "measured":
            stats.append(
                f"<tr><td>{escape(result['name'])}</td><td colspan='8'>Unavailable: {escape(result.get('reason', 'not run'))}</td></tr>"
            )
            continue
        for metric, values in result["statistics"].items():
            stats.append(
                "<tr>"
                + "".join(
                    f"<td>{escape(value)}</td>"
                    for value in [
                        result["name"],
                        metric,
                        values["n"],
                        *(
                            f"{values[key]:.5g}"
                            for key in ["mean", "median", "stdev", "p95", "min", "max"]
                        ),
                    ]
                )
                + "</tr>"
            )
    charts = []
    titles = [
        "KEM computation",
        "Handshake distributions",
        "CPU and memory",
        "Bandwidth overhead",
        "Messages and re-keying",
        "Configured network delay",
    ]
    for name, title in zip(CHARTS, titles):
        source = (output_dir / (name + ".svg")).read_text()
        svg = source[source.index("<svg") :]
        charts.append(
            f'<section><h2>{escape(title)}</h2><div class="chart">{svg}</div></section>'
        )
    limitations = "".join(
        f"<li>{escape(value)}</li>" for value in report["limitations"]
    )
    method = "\n".join(f"{key}: {value}" for key, value in metadata.items())
    content = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Crytosage · Cryptographic research report</title><style>
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#f4f5ef;color:#203d31;font:16px/1.65 system-ui,sans-serif}main{max-width:1180px;margin:auto;padding:44px 24px}header{border-bottom:2px solid #245641;padding-bottom:28px;margin-bottom:32px}.eyebrow{letter-spacing:.13em;text-transform:uppercase;font-size:12px}h1{font:normal clamp(30px,5vw,48px)/1.15 Georgia,serif;max-width:850px;margin:14px 0}h2{font-size:23px}section{background:#fffefb;padding:24px;margin:24px 0;border:1px solid #d2d9cf;border-radius:12px}p{max-width:85ch}.chart svg{width:100%;height:auto}.chart{overflow:hidden}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #dce1d8}th{background:#e8eee3;position:sticky;top:0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.6 ui-monospace,monospace}.scroll{overflow:auto}.badge{display:inline-block;padding:5px 12px;background:#e5eddc;border-radius:20px;font-size:13px}footer{border-top:1px solid #c6d1c2;margin-top:36px;padding-top:18px;font-size:13px}@media print{body{background:white}main{padding:0}section{break-inside:avoid}.scroll{overflow:visible}h1{font-size:34px}table{font-size:9px}th,td{padding:3px}.chart svg{max-height:420px}}
</style></head><body><main><header><div class="eyebrow">Crytosage / University research prototype</div><h1>Post-quantum cryptographic evaluation</h1>"""
    content += f"<span class='badge'>{escape(metadata['trials'])} measured trials per available KEM</span><p>Generated {escape(metadata['created_at'])}. Execution: {escape(metadata.get('environment', {}).get('kind', 'unclassified'))} on {escape(metadata.get('os', 'unavailable'))}.</p></header>"
    content += f"<section><h2>Observed findings</h2><ul>{cards}</ul><p>All measurements below are actual recorded operations. Missing capabilities remain unavailable. Passing experiments are not proof of a secure protocol.</p></section>"
    content += "".join(charts)
    content += '<section><h2>Summary statistics</h2><p>Metric suffixes identify units: _ms milliseconds, _bytes bytes, _percent percent. Sample standard deviation; nearest-rank P95. Raw rows are in the accompanying trials.csv and results.json.</p><div class="scroll"><table><thead><tr>'
    content += "".join(
        f"<th>{label}</th>"
        for label in [
            "Algorithm",
            "Metric",
            "N",
            "Mean",
            "Median",
            "Std dev",
            "P95",
            "Min",
            "Max",
        ]
    )
    content += (
        "</tr></thead><tbody>" + "".join(stats) + "</tbody></table></div></section>"
    )
    content += f"<section><h2>Methodology, versions and hardware</h2><pre>{escape(method)}</pre><h2>Limits of interpretation</h2><ul>{limitations}</ul>"
    content += "<p>The benchmark restricts each handshake to the KEM under test. The total includes signed policy advertisements, the admissible ephemeral KEM public key, key confirmations and key derivation.</p><p>Network measurements use actual loopback sockets. A configured artificial delay is inserted at test endpoints before every send; it is not evidence about a physical WAN. Do not subtract an opaque-payload roundtrip from a protocol exchange to claim exact transmission overhead. CPU/RSS observations cover the KEM trial process and can include other process threads; cumulative high-water RSS is not attributable to an individual algorithm.</p></section>"
    content += "<footer>Research prototype · HQC-3 remains experimental · No production certification, formal security proof or platform portability claim is implied by this report.</footer></main></body></html>"
    (output_dir / "report.html").write_text(content)
