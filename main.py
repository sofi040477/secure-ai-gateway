"""CLI interactiva de la aplicación de IA protegida.

Comandos:
  <texto>                    consulta normal
  /ext <texto>               consulta con contenido externo (archivo/web/correo) simulado
  /file <ruta> | <pregunta>  usa un archivo como contenido externo
  /pendientes                lista solicitudes en REVIEW
  /aprobar <ID> | /rechazar <ID>   decisión del HUMANO EN EL CIRCUITO
  /salir
"""
import argparse
from pathlib import Path

from config import Config
from pipeline import SecureGateway


def show(r):
    print(f"  [{r['action']}] Event ID: {r['event_id']} (score={r['score'] if 'score' in r else '-'})")
    for reason in r.get("reasons", []):
        print(f"    - {reason}")
    print("  >", r.get("response") or r.get("message"))
    if r.get("alert"):
        print(f"  !! ALERTA DE CORRELACIÓN: {r['alert']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", default="estudiante")
    ap.add_argument("--ip", default="127.0.0.1")
    args = ap.parse_args()
    gw = SecureGateway(Config.from_env())
    print(__doc__)
    while True:
        try:
            line = input(f"{args.user}> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        if line == "/salir":
            break
        if line == "/pendientes":
            for k, v in gw.queue.pending().items():
                print(f"  {k} user={v['user']} motivo={v['reasons']}")
        elif line.startswith(("/aprobar ", "/rechazar ")):
            cmd, rid = line.split(maxsplit=1)
            show(gw.resolve_review(rid.strip(), cmd == "/aprobar", reviewer=args.user))
        elif line.startswith("/ext "):
            show(gw.handle(args.user, "Resume el siguiente contenido", external=line[5:], ip=args.ip))
        elif line.startswith("/file "):
            path, _, question = line[6:].partition("|")
            show(gw.handle(args.user, question.strip() or "Resume el archivo",
                           external=Path(path.strip()).read_text(encoding="utf-8"), ip=args.ip))
        else:
            show(gw.handle(args.user, line, ip=args.ip))


if __name__ == "__main__":
    main()
