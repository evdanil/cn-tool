"""One page of the configuration matches the worker holds (the rows of a finished configuration search).

The page is cut from the complete result, filtered and sorted first, so a page never depends on what was shown before.
A query that names no column filters every column (the table's quick filter, ``tables.cn_table``). Pure: the worker
calls it with its retained rows and a validated query (``protocol.validate``).
"""
import json
from collections import Counter

# A row is [search term, device, line number (from 0), the matching line, the file].
COLUMN_INDEX = {'device': 1, 'line': 2, 'configuration': 3, 'search': 0, 'file': 4}
PAGE_BYTES = 1024 * 1024 - 1024  # the protocol allows 1 MiB for a result: the page keeps room for its envelope


def config_search_page(rows, query):
    """Return a bounded configuration page; the retained result itself is never reordered."""
    from .config_demob import ordered_page_rows

    page = dict(job_id=query['job_id'], offset=query['offset'], query_id=query['query_id'],
                rows=[], total=0, next_offset=None, status='unavailable', device_counts={})
    if 'sort_by' in query:
        page.update({key: query[key] for key in ('sort_by', 'descending', 'filter_by', 'filter_text')})
        page['overall_total'] = 0
    if rows is None:
        return page
    ordered = ordered_page_rows(rows, value=lambda row, key: row[COLUMN_INDEX[key]],
                                sort_by=query.get('sort_by'), descending=query.get('descending', False),
                                filter_by=query.get('filter_by'), filter_text=query.get('filter_text', ''),
                                numeric=('line',), filter_keys=tuple(COLUMN_INDEX))
    if not query.get('sort_by'):
        # The search's own order is by line number, which mixes the devices. The table heads each device's rows once
        # (``config_table.by_device``), so the rows of a device are kept together: devices in the order the search
        # found them, each device's rows in the order they had.
        first = {}
        ordered = sorted(ordered, key=lambda row: first.setdefault(row[1], len(first)))
    if query['offset'] > len(ordered):
        return page
    page.update(total=len(ordered), status='ready')
    per_device = Counter(row[1] for row in ordered)  # matches of each device under the filter, whatever the page
    if 'overall_total' in page:
        page['overall_total'] = len(rows)
    index = query['offset']
    size = len(json.dumps(page, ensure_ascii=False).encode('utf-8'))  # the page with no row; each row adds its own and ", "
    while index < len(ordered) and len(page['rows']) < query['limit']:
        row_size = len(json.dumps(ordered[index], ensure_ascii=False).encode('utf-8')) + (2 if page['rows'] else 0)
        device = ordered[index][1]
        if device not in page['device_counts']:  # a count: `"device": 12, ` (five digits at most: the protocol allows 10,000)
            row_size += len(json.dumps(device, ensure_ascii=False).encode('utf-8')) + 9
        if size + row_size > PAGE_BYTES:
            if not page['rows']:
                page.update(total=0, next_offset=None, status='unavailable', device_counts={})
                if 'overall_total' in page:
                    page['overall_total'] = 0
                return page
            break
        page['rows'].append(ordered[index])
        page['device_counts'][device] = per_device[device]
        size += row_size
        index += 1
    page['next_offset'] = index if index < len(ordered) else None
    return page
