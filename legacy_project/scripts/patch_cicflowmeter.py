from pathlib import Path
import site

sniffer_path = None

for base in site.getsitepackages():
    p = Path(base) / "cicflowmeter" / "sniffer.py"
    if p.exists():
        sniffer_path = p
        break

if sniffer_path is None:
    raise SystemExit("[ERRO] cicflowmeter/sniffer.py não encontrado")

text = sniffer_path.read_text()

start = text.index("def create_sniffer(")
end = text.index("\ndef process_directory_merged", start)

new_func = '''def create_sniffer(
    input_file, input_interface, output_mode, output, input_directory=None, fields=None, verbose=False
):
    assert sum([input_file is None, input_interface is None, input_directory is None]) == 2, (
        "Provide exactly one: interface, file, or directory input"
    )

    if isinstance(fields, str) and fields:
        fields = fields.split(",")
    else:
        fields = None

    session = FlowSession(
        output_mode=output_mode,
        output=output,
        fields=fields,
        verbose=verbose,
    )

    _start_periodic_gc(session, interval=GC_INTERVAL)

    if input_file:
        sniffer = AsyncSniffer(
            offline=input_file,
            filter="ip and (tcp or udp)",
            prn=session.process,
            store=False,
        )
    else:
        sniffer = AsyncSniffer(
            iface=input_interface,
            filter="ip and (tcp or udp)",
            prn=session.process,
            store=False,
        )
    return sniffer, session

'''

sniffer_path.write_text(text[:start] + new_func + text[end+1:])
print("[OK] cicflowmeter corrigido:", sniffer_path)
