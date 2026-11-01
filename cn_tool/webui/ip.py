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
    table(rows)
