from __future__ import annotations

import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1] / "skills" / "generative-ui"
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class LoopdyCardSkillTests(unittest.TestCase):
    def test_skill_routes_new_compositions_to_the_card_reference(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")

        self.assertIn("Loopdy Cards", skill)
        self.assertIn("`loopdy_render_card`", skill)
        self.assertIn("references/loopdy-cards.md", skill)
        self.assertIn("typed v2", skill)
        self.assertIn("visual parity", skill)

    def test_reference_states_the_static_data_and_non_executable_boundary(self) -> None:
        reference = (SKILL_ROOT / "references" / "loopdy-cards.md").read_text(
            encoding="utf-8"
        )

        for required in (
            "`data_sources` must be an empty array",
            "does not fetch card data from the network",
            "no downloaded code",
            "HTML",
            "WebViews",
            "credentials",
            "secrets",
        ):
            with self.subTest(required=required):
                self.assertIn(required, reference)

    def test_reference_covers_the_finite_language_and_static_examples(self) -> None:
        reference = (SKILL_ROOT / "references" / "loopdy-cards.md").read_text(
            encoding="utf-8"
        )

        for component in (
            "`card`",
            "`vstack`",
            "`hstack`",
            "`grid`",
            "`text`",
            "`metric`",
            "`badge`",
            "`progress`",
            "`chart`",
            "`table`",
            "`list`",
            "`divider`",
            "`spacer`",
            "`image`",
        ):
            self.assertIn(component, reference)
        for example in ("Build health", "Project status", "Comparison table"):
            self.assertIn(example, reference)

    def test_release_documents_do_not_advertise_live_card_requests(self) -> None:
        documents = (
            REPOSITORY_ROOT / "README.md",
            REPOSITORY_ROOT / "docs" / "LOOPDY_CARDS.md",
            REPOSITORY_ROOT / "docs" / "SECURITY_AND_PRIVACY.md",
            REPOSITORY_ROOT / "docs" / "ARCHITECTURE.md",
            REPOSITORY_ROOT / "plugins" / "loopdy" / "README.md",
            REPOSITORY_ROOT / "plugins" / "loopdy" / "PROTOCOL.md",
        )
        prohibited = (
            "Opening a live card",
            "Direct HTTPS GET",
            "device fetches declared data sources",
            "makes refresh requests",
            "receive direct HTTPS requests",
        )

        for document in documents:
            content = document.read_text(encoding="utf-8")
            with self.subTest(document=document.name):
                self.assertIn("build 3", content.lower())
                for phrase in prohibited:
                    self.assertNotIn(phrase, content)


if __name__ == "__main__":
    unittest.main()
