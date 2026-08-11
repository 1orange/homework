from report_worker import render


def test_render_includes_tenant():
    out = render.render("acme", [{"sku": "SKU-1001", "quantity": 42}])
    assert "acme" in out
    assert "SKU-1001: 42" in out
