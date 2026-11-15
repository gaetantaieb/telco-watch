"""The Claude Code subagents named in CLAUDE.md exist and are well formed."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
AGENTS = ["product-owner", "architect", "qa"]


def frontmatter(path):
    text = path.read_text()
    assert text.startswith("---\n"), f"{path} has no frontmatter"
    head, body = text[4:].split("\n---\n", 1)
    return yaml.safe_load(head), body


@pytest.mark.parametrize("name", AGENTS)
def test_agents_are_defined_with_a_name_description_and_prompt(name):
    meta, body = frontmatter(ROOT / ".claude" / "agents" / f"{name}.md")
    assert meta["name"] == name
    assert len(meta["description"]) > 50
    assert body.strip()


@pytest.mark.parametrize("name", AGENTS)
def test_claude_md_tells_to_use_each_agent(name):
    assert f"`{name}`" in (ROOT / "CLAUDE.md").read_text()


def test_the_architect_and_qa_cannot_change_production_code():
    architect, _ = frontmatter(ROOT / ".claude" / "agents" / "architect.md")
    assert not {"Edit", "Write"} & set(architect["tools"].split(", "))
    qa, _ = frontmatter(ROOT / ".claude" / "agents" / "qa.md")
    assert "never production code" in qa["description"]
