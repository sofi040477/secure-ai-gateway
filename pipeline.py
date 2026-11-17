"""Gateway seguro: orquesta Frontera de confianza -> Normalización -> Detección ->
Motor de políticas -> (Humano en el circuito) -> Agente -> Filtro de salida -> Auditoría.

FALLA SEGURA: cualquier excepción termina en BLOCK y sin respuesta del agente.
"""
import sys
import uuid

import dlp
from agent import AIAgent
from audit import AuditLogger
from correlation import Correlator, RateLimiter
from detector import scan
from normalizer import normalize
from policy_engine import Context, PolicyEngine, PolicyError
from review_queue import ReviewQueue


class SecureGateway:
    def __init__(self, cfg, agent=None, now=None):
        self.cfg = cfg
        self.audit = AuditLogger(cfg)
        self.queue = ReviewQueue(cfg.log_dir)
        self.agent = agent or AIAgent(cfg.api_key, cfg.model)
        self.engine, self.policy_error = None, None
        try:
            self.engine = PolicyEngine.from_file(cfg.policy_file)
        except PolicyError as exc:              # política inválida => denegar todo
            self.policy_error = str(exc)
        kw = {"now": now} if now else {}
        corr_cfg = self.engine.policy["correlation"] if self.engine else \
            {"window_s": 300, "block_threshold": 3, "lockout_s": 300, "ip_distinct_users": 3}
        self.limiter, self.correlator = RateLimiter(**kw), Correlator(corr_cfg, **kw)

    # ------------------------------------------------------------------ API pública
    def handle(self, user, prompt, external=None, ip="127.0.0.1", session="-"):
        req = uuid.uuid4().hex[:8]
        try:
            return self._handle(req, user, prompt, external, ip, session)
        except Exception as exc:                # FALLA SEGURA
            return self._fail_safe(req, user, ip, exc)

    def resolve_review(self, review_id, approve, reviewer="humano"):
        try:
            item = self.queue.get(review_id)
            if not item or item["status"] != "PENDING":
                raise ValueError("Revisión inexistente o ya resuelta")
            self.queue.resolve(review_id, approve, reviewer)
            if not approve:
                self.audit.emit("REVIEW_REJECTED", ref=review_id, reviewer=reviewer, user=item["user"])
                return {"action": "BLOCK", "event_id": review_id, "response": None,
                        "message": "Solicitud rechazada por el revisor humano."}
            self.audit.emit("REVIEW_APPROVED", ref=review_id, reviewer=reviewer, user=item["user"])
            response = self._answer(review_id, item["user"], item["prompt"], item["external"])
            return {"action": "ALLOW", "event_id": review_id, "response": response,
                    "message": "Aprobada por el revisor humano."}
        except Exception as exc:
            return self._fail_safe(review_id, "reviewer", "-", exc)

    # ------------------------------------------------------------------ internos
    def _handle(self, req, user, prompt, external, ip, session):
        if self.engine is None:
            raise PolicyError(self.policy_error or "Motor de políticas no disponible")
        pol = self.engine.policy
        lim = pol["limits"]

        # 1) FRONTERA DE CONFIANZA: todo lo que llega es no confiable hasta pasar los controles
        rate_exceeded = self.limiter.hit(user, lim["rate_limit_requests"], lim["rate_limit_window_s"])
        locked = self.correlator.is_locked(user)

        # 2) NORMALIZACIÓN
        n_prompt = normalize(prompt, lim["max_prompt_chars"])
        n_ext = normalize(external, lim["max_external_chars"]) if external else None

        # 3) DETECCIÓN (directa e indirecta) + DLP de entrada
        s_prompt = scan(n_prompt)
        s_ext = scan(n_ext, external=True) if n_ext else None
        kinds = dlp.find_sensitive(n_prompt.text + (" " + n_ext.text if n_ext else ""))

        # 4) MOTOR DE POLÍTICAS
        decision = self.engine.evaluate(Context(n_prompt, s_prompt, n_ext, s_ext, kinds, rate_exceeded, locked))
        action = decision.action
        event_id = self.audit.new_event_id()
        preview = dlp.redact(n_prompt.text.replace("\n", " "))[0][:80]

        # 5) AUDITORÍA (obligatoria: si falla, AuditError => falla segura)
        for scan_, mnem in ((s_prompt, "PROMPT_INJECTION"), (s_ext, "PROMPT_INJECTION_INDIRECT")):
            if scan_ and scan_.findings:
                self.audit.emit(mnem, ref=event_id, user=user, src_ip=ip,
                                rules=",".join(f["rule"] for f in scan_.findings), score=scan_.score)
        self.audit.emit(f"REQ_{action}", event_id=event_id, user=user, src_ip=ip, session=session,
                        req=req, score=decision.score,
                        rules=",".join(r["id"] for r in decision.rules),
                        flags=",".join(n_prompt.flags) or "-", input=preview)

        result = {"event_id": event_id, "action": action, "score": decision.score,
                  "reasons": decision.reasons, "response": None, "message": ""}

        if action == "ALLOW":
            result["response"] = self._answer(event_id, user, n_prompt.text, n_ext.text if n_ext else None)
        elif action == "REVIEW":
            self.queue.add(event_id, user, n_prompt.text, n_ext.text if n_ext else None, decision.reasons)
            result["message"] = f"Solicitud en revisión humana. ID de revisión: {event_id}"
        else:
            result["message"] = f"Solicitud bloqueada por política de seguridad. Event ID: {event_id}"

        # 6) CORRELACIÓN
        alert = self.correlator.record(user, ip, action)
        if alert:
            self.audit.emit("CORRELATION_ALERT", ref=event_id, **alert)
            result["alert"] = alert
        return result

    def _answer(self, event_id, user, prompt_text, external_text):
        raw = self.agent.ask(prompt_text, external_text)
        safe, kinds = dlp.output_guard(raw)      # filtro de salida
        if kinds:
            self.audit.emit("DLP_OUTPUT_REDACTED", ref=event_id, user=user, kinds=",".join(kinds))
        return safe

    def _fail_safe(self, req, user, ip, exc):
        event_id = self.audit.new_event_id()
        try:
            self.audit.emit("FAIL_SAFE", event_id=event_id, req=req, user=user, src_ip=ip,
                            error=type(exc).__name__, detail=str(exc)[:100], action="BLOCK")
        except Exception as audit_exc:
            print(f"[FALLA SEGURA] auditoría no disponible: {audit_exc}", file=sys.stderr)
        return {"event_id": event_id, "action": "BLOCK", "score": 0,
                "reasons": [f"FAIL-SAFE: {type(exc).__name__}"], "response": None,
                "message": f"Falla segura: solicitud denegada. Event ID: {event_id}"}
