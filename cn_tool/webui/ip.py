"""Flat IP results and entry point for the shared session page."""


def render_ip(controller, scope):
    from .subnets import render_subnets
    render_subnets(controller, scope, lookup_type='ip')


def render_ip_results(snapshot, data_table):
    """The addresses of an IP result as one table (``subnets.data_table``): the address stays in view, and ``DUID`` is
    drawn whenever the rows carry it, because the input decided that, not what came back."""
    rows = snapshot.result.get('rows', [])
    if not rows:
        return
    data_table(rows, name='ip', label='IP addresses', table_id='ip', lead=('IP', 'Status', 'Network view'),
               sticky='IP', keep=('DUID',), send=True)
