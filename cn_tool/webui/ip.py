"""Flat IP results and entry point for the shared session page."""


def render_ip(controller):
    from .subnets import render_subnets
    render_subnets(controller, lookup_type='ip')


def render_ip_results(snapshot, table):
    from nicegui import ui

    if snapshot.latest_attempt_id and snapshot.latest_attempt_id != snapshot.result_job_id:
        ui.label('Previous lookup results').classes('text-weight-bold')
    rows = snapshot.result.get('rows', [])
    if not rows:
        return
    with ui.column().classes('cn-compact-summary w-full'):
        for row in rows:
            address = str(row.get('IP') or '')
            network_view = str(row.get('Network view') or '')
            status_value = str(row.get('Status') or '')
            with ui.column().classes('cn-summary-row'):
                ui.label(f'Address: {address}').classes('cn-network cn-summary-network')
                ui.label(f'View: {network_view or "—"}').classes('cn-muted')
                ui.label(f'Status: {status_value or "—"}').classes('cn-summary-status')
                secondary = [(key, value) for key, value in row.items()
                             if key not in {'IP', 'Network view', 'Status', 'id', '__row'}]
                if secondary:
                    identity = ', '.join(value for value in (address, network_view) if value)
                    with ui.expansion(f'More fields for {identity}').classes('w-full'):
                        for key, value in secondary:
                            ui.label(f'{key}: {value}')
    with ui.column().classes('cn-desktop-summary w-full'):
        table(rows)
