# gatekeeper/protected_pipeline.py
from gatekeeper.classifier import InjectionClassifier
from gatekeeper.output_scanner import scan_output, redact_output
from gatekeeper.hardened_assistant import run_hardened_assistant


class ProtectedPipeline:
    """
    Production-grade defense pipeline combining 3 layers:
    Layer 1 — Input Classifier (DistilBERT)
    Layer 3 — Hardened Assistant (strict system prompt)
    Layer 5 — Output Scanner (leak detection)
    """

    def __init__(
        self,
        classifier_threshold: float = 0.5,
        redact_mode: bool = False,
        verbose: bool = True
    ):
        """
        classifier_threshold: probability above which input is blocked.
        redact_mode: if True, redact leaks instead of blocking entirely.
        verbose: print layer-by-layer decisions.
        """
        self.verbose = verbose
        self.redact_mode = redact_mode

        # ── load Layer 1 ─────────────────────────────────
        if self.verbose:
            print("\n  📦 Loading defense pipeline...")
        self.classifier = InjectionClassifier(threshold=classifier_threshold)

        # statistics
        self.stats = {
            "total_requests":       0,
            "blocked_at_layer_1":   0,   # input classifier
            "blocked_at_layer_3":   0,   # hardened assistant refused
            "blocked_at_layer_5":   0,   # output scanner caught leak
            "allowed_through":      0,
        }

    # ── MAIN PIPELINE ────────────────────────────────────────
    def process(self, user_input: str) -> dict:
        """
        Run user input through all 3 defense layers.
        Returns final response + metadata.
        """
        self.stats["total_requests"] += 1

        if self.verbose:
            self._print_input(user_input)

        # ── LAYER 1 — INPUT CLASSIFIER ──────────────────────
        layer1_result = self.classifier.predict(user_input)

        if self.verbose:
            self._print_layer1(layer1_result)

        if layer1_result["verdict"] == "BLOCK":
            self.stats["blocked_at_layer_1"] += 1
            return self._build_response(
                blocked_at="LAYER_1",
                response="🚫 Request blocked by input classifier.",
                layer1=layer1_result,
                layer3=None,
                layer5=None
            )

        # ── LAYER 3 — HARDENED ASSISTANT ────────────────────
        if self.verbose:
            print("\n  🛡️  Layer 3: Hardened Assistant processing...")

        raw_response = run_hardened_assistant(user_input)

        # detect if assistant refused
        refused_keywords = [
            "cannot", "won't", "will not", "can't",
            "not allowed", "unable to", "refuse",
            "security policy", "violates"
        ]
        refused = any(
            keyword in raw_response.lower()
            for keyword in refused_keywords
        )

        if self.verbose:
            self._print_layer3(raw_response, refused)

        if refused:
            self.stats["blocked_at_layer_3"] += 1

        # ── LAYER 5 — OUTPUT SCANNER ────────────────────────
        layer5_result = scan_output(raw_response)

        if self.verbose:
            self._print_layer5(layer5_result)

        if layer5_result["verdict"] == "BLOCK":
            self.stats["blocked_at_layer_5"] += 1

            if self.redact_mode:
                final_response = redact_output(raw_response)
                final_response += "\n\n⚠️  Some content was redacted for security."
            else:
                final_response = (
                    "🚫 Response blocked — output scanner detected "
                    "potential sensitive data leak."
                )

            return self._build_response(
                blocked_at="LAYER_5",
                response=final_response,
                layer1=layer1_result,
                layer3={"refused": refused, "raw_response": raw_response[:200]},
                layer5=layer5_result
            )

        # ── ALL CLEAR ───────────────────────────────────────
        self.stats["allowed_through"] += 1
        return self._build_response(
            blocked_at=None,
            response=raw_response,
            layer1=layer1_result,
            layer3={"refused": refused, "raw_response": raw_response[:200]},
            layer5=layer5_result
        )

    # ── RESPONSE BUILDER ─────────────────────────────────────
    def _build_response(self, blocked_at, response, layer1, layer3, layer5):
        return {
            "blocked": blocked_at is not None,
            "blocked_at": blocked_at,
            "response": response,
            "layers": {
                "layer_1_classifier": layer1,
                "layer_3_assistant":  layer3,
                "layer_5_scanner":    layer5
            }
        }

    # ── STATISTICS ───────────────────────────────────────────
    def print_stats(self):
        """Print pipeline statistics."""
        total = self.stats["total_requests"]
        if total == 0:
            print("\n  No requests processed yet.")
            return

        print("\n" + "=" * 60)
        print("  📊 PIPELINE STATISTICS")
        print("=" * 60)
        print(f"  Total requests:        {total}")
        print(f"  Blocked at Layer 1:    {self.stats['blocked_at_layer_1']} "
              f"({self.stats['blocked_at_layer_1']/total:.0%})")
        print(f"  Blocked at Layer 3:    {self.stats['blocked_at_layer_3']} "
              f"({self.stats['blocked_at_layer_3']/total:.0%})")
        print(f"  Blocked at Layer 5:    {self.stats['blocked_at_layer_5']} "
              f"({self.stats['blocked_at_layer_5']/total:.0%})")
        print(f"  Allowed through:       {self.stats['allowed_through']} "
              f"({self.stats['allowed_through']/total:.0%})")
        print("=" * 60)

    # ── PRINT HELPERS ────────────────────────────────────────
    def _print_input(self, text: str):
        print("\n" + "─" * 60)
        print(f"  📥 INPUT: {text[:80]}")
        print("─" * 60)

    def _print_layer1(self, result: dict):
        icon = "🚫" if result["is_injection"] else "✅"
        print(f"\n  {icon} Layer 1 (Classifier): "
              f"{result['verdict']} "
              f"({result['injection_probability']:.0%} injection)")

    def _print_layer3(self, response: str, refused: bool):
        icon = "🚫" if refused else "✅"
        status = "REFUSED" if refused else "COMPLIED"
        print(f"\n  {icon} Layer 3 (Assistant): {status}")
        print(f"     Response: {response[:100]}...")

    def _print_layer5(self, result: dict):
        icon = "🚫" if result["verdict"] == "BLOCK" else "✅"
        print(f"\n  {icon} Layer 5 (Output Scanner): {result['verdict']}")
        if result["findings"]:
            print(f"     Findings: {result['finding_count']} issues")


# ── DEMO / CLI MODE ──────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  🛡️  PROTECTED PIPELINE")
    print("  3-Layer Defense System")
    print("=" * 60)
    print("  Layer 1: DistilBERT Input Classifier")
    print("  Layer 3: Hardened Assistant")
    print("  Layer 5: Output Scanner")
    print("=" * 60)

    pipeline = ProtectedPipeline(verbose=True)

    print("\n  Type 'exit' to quit, 'stats' to see statistics.\n")

    while True:
        user_input = input("\nYou: ").strip()

        if user_input.lower() in ["exit", "quit"]:
            pipeline.print_stats()
            break

        if user_input.lower() == "stats":
            pipeline.print_stats()
            continue

        if not user_input:
            continue

        result = pipeline.process(user_input)
        print(f"\n  💬 Final response:")
        print(f"     {result['response'][:300]}")