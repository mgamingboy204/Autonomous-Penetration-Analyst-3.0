from pathlib import Path


def generate_report(run_ctx, context):
    template_text = Path("templates/report_template.html").read_text()
    try:
        from jinja2 import Template
        html = Template(template_text).render(**context)
    except Exception:
        html = template_text
        for k, v in context.items():
            html = html.replace("{{ " + k + " }}", str(v))
    run_ctx.report_dir.mkdir(parents=True, exist_ok=True)
    out = run_ctx.report_dir / "report.html"
    out.write_text(html)
    return out
