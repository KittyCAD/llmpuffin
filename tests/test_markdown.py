"""Tests for Markdown rendering and XSS sanitization."""

from llmpuffin.markdown import render_markdown


class TestRenderMarkdown:
    def test_empty_string(self):
        assert render_markdown("") == ""

    def test_bold(self):
        result = render_markdown("**bold**")
        assert "<strong>bold</strong>" in result

    def test_fenced_code_block(self):
        result = render_markdown("```python\nprint('hi')\n```")
        assert "<code>" in result
        assert "print" in result

    def test_table(self):
        md = "| a | b |\n|---|---|\n| 1 | 2 |"
        result = render_markdown(md)
        assert "<table>" in result

    def test_link_gets_rel(self):
        result = render_markdown("[link](https://example.com)")
        assert 'rel="noopener noreferrer"' in result


class TestXssSanitization:
    def test_script_tag_stripped(self):
        result = render_markdown("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "alert" not in result

    def test_onclick_stripped(self):
        result = render_markdown('<div onclick="alert(1)">hi</div>')
        assert "onclick" not in result

    def test_onerror_stripped(self):
        result = render_markdown('<img onerror="alert(1)" src="x">')
        assert "onerror" not in result

    def test_javascript_url_stripped(self):
        result = render_markdown('<a href="javascript:alert(1)">click</a>')
        assert "javascript:" not in result

    def test_iframe_stripped(self):
        result = render_markdown('<iframe src="https://evil.com"></iframe>')
        assert "<iframe" not in result
