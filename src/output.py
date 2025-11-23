def render_table(results, verbose: bool, show_proto: bool) -> None:
    results_list = list(results)
    if not results_list:
        print("No open ports found")
        return

    columns = [("PROTO", lambda r: r.proto), ("PORT", lambda r: str(r.port))]
    if verbose:
        columns.append(("TIME,ms", lambda r: f"{r.elapsed_ms:.2f}"))
    if show_proto:
        columns.append(("PROTOCOL", lambda r: r.app_proto or "-"))

    rows = []
    for res in results_list:
        row = [getter(res) for _, getter in columns]
        rows.append(row)

    widths = []
    for idx, (title, _) in enumerate(columns):
        cell_width = max(len(title), max(len(row[idx]) for row in rows))
        widths.append(cell_width)

    header = " | ".join(title.ljust(widths[i]) for i, (title, _) in enumerate(columns))
    separator = "-+-".join("-" * widths[i] for i in range(len(columns)))
    print(header)
    print(separator)
    for row in rows:
        line = " | ".join(row[i].ljust(widths[i]) for i in range(len(columns)))
        print(line)
