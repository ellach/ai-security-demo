# injector/graph.py
from injector.payloads import ALL_CATEGORIES, ATTACK_GRAPH


class AttackGraph:
    """
    Manages the attack strategy graph.
    Decides which attack category to try next when current one fails.
    """

    def __init__(self):
        self.categories = ALL_CATEGORIES   # all available payloads
        self.graph = ATTACK_GRAPH          # which category leads to which
        self.visited = set()               # categories already tried
        self.current = None                # current category
        self.start_node = "direct"         # always start with direct attack
        self.results = {}                  # store results per category

    # ── NODE NAVIGATION ──────────────────────────────────────
    def start(self) -> str:
        """Reset the graph and return the starting category."""
        self.visited = set()
        self.current = self.start_node
        self.visited.add(self.current)
        print(f"\n  🗺️  Attack graph started")
        print(f"  📍 Starting node: {self.current}")
        return self.current

    def next_node(self) -> str | None:
        """
        Decide which category to try next.
        Returns None if all paths exhausted.
        """
        if self.current is None:
            return None

        # get all possible next categories from current node
        candidates = self.graph.get(self.current, [])

        # filter out already visited
        unvisited = [c for c in candidates if c not in self.visited]

        if unvisited:
            self.current = unvisited[0]
            self.visited.add(self.current)
            print(f"\n  ➡️  Moving to next node: {self.current}")
            return self.current

        # current branch exhausted — fallback to any unvisited
        all_unvisited = [
            c for c in self.categories.keys()
            if c not in self.visited
        ]

        if all_unvisited:
            self.current = all_unvisited[0]
            self.visited.add(self.current)
            print(f"\n  🔀 Fallback to: {self.current}")
            return self.current

        # all categories exhausted
        self.current = None
        print("\n  🛑 All attack paths exhausted")
        return None

    # ── PAYLOAD ACCESS ───────────────────────────────────────
    def get_payloads(self, category: str) -> list[str]:
        """Get all payloads for a given category."""
        return self.categories.get(category, [])

    # ── RESULT TRACKING ──────────────────────────────────────
    def record_result(self, category: str, payload: str, result: dict):
        """Record the result of an attack attempt."""
        if category not in self.results:
            self.results[category] = []

        self.results[category].append({
            "payload": payload,
            "success": result["success"],
            "confidence": result["confidence"],
            "reason": result["reason"],
            "leaked_data": result["leaked_data"]
        })

    def get_best_result(self) -> dict | None:
        """Return the most successful attack result across all categories."""
        for category, attempts in self.results.items():
            for attempt in attempts:
                if attempt["success"] == True:
                    return {
                        "category": category,
                        **attempt
                    }

        # check for partial success
        for category, attempts in self.results.items():
            for attempt in attempts:
                if attempt["success"] == "PARTIAL":
                    return {
                        "category": category,
                        **attempt
                    }

        return None

    # ── STATE INFO ───────────────────────────────────────────
    def get_status(self) -> dict:
        """Return current graph state."""
        return {
            "current_category": self.current,
            "visited_categories": list(self.visited),
            "remaining_categories": [
                c for c in self.categories.keys()
                if c not in self.visited
            ],
            "exhausted": self.current is None and len(self.visited) > 0
        }

    def print_summary(self):
        """Print a full summary of the attack run."""
        print("\n" + "=" * 60)
        print("  📊 ATTACK SUMMARY")
        print("=" * 60)

        for category, attempts in self.results.items():
            print(f"\n  Category: {category.upper()}")
            for i, attempt in enumerate(attempts, 1):
                status = "✅" if attempt["success"] == True else \
                         "⚠️ " if attempt["success"] == "PARTIAL" else "❌"
                print(f"    {status} Attempt {i}: {attempt['reason']}")

        best = self.get_best_result()
        if best:
            print(f"\n  🎯 BEST RESULT: {best['category'].upper()}")
            print(f"  Confidence: {best['confidence']}")
            print(f"  Leaked: {best['leaked_data']}")
        else:
            print("\n  🛡️  All attacks failed — target is well defended")

        print("=" * 60)

    # ── RESET ────────────────────────────────────────────────
    def reset(self):
        """Reset graph for a fresh attack run."""
        self.visited = set()
        self.current = None
        self.results = {}
        print("\n  🔄 Attack graph reset")