"""The line at the foot of every web UI page: the version in use and the copyright holder."""
from cn_tool import cn_buildstamp

# The line follows the page's content and takes no part in it: it is last in the page's column whatever a page
# adds later (order), it is in the flow and so covers nothing, and it lets every click through.
FOOTER_CSS = '''
.cn-footer { order:9999; width:100%; margin:0; padding-top:4px; text-align:center; color:var(--cn-muted); font-size:var(--cn-text-small);
  line-height:1.4; overflow-wrap:anywhere; pointer-events:none; }
'''


def footer_text():
    """``cn-tool v0.12.3 · © Evgeny Danilchenko``; without the version when the package has no version file."""
    stamp = cn_buildstamp.build_stamp()
    name = f'cn-tool v{stamp.package_version}' if stamp else 'cn-tool'
    return f'{name} · {cn_buildstamp.copyright_line()}'


def render_footer():
    from nicegui import ui

    from .scope import add_once

    add_once(ui.context.client, 'footer', css=FOOTER_CSS)
    with ui.element('footer').classes('cn-footer'):
        ui.label(footer_text())
