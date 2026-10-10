"""
Infoblox network views: which view a lookup searches, how to scope a request to it and when to show it.

Every Infoblox lookup asks the same four questions, and this module answers all of them so the
lookup modules only call it:

* which network view to search (``--view``, ``--all-views`` or ``[api] network_view``);
* how to scope a request URI to that view (``scope_network`` and ``scope_dns``);
* whether the view column shows in the result (``ViewScope.column`` and ``ViewScope.result_column``);
* which views to ask when none is chosen (``ViewScope.all_views``, ``request_in_views`` and
  ``merge_view_results``).

The last one exists because the WAPI does not search every view when a request names none. The
searches by network (``network?network=``, ``network_container=``, an extensible attribute or a
comment) and by record name span the views, but a request about an address, or about the objects of
one network (``ipv4address?ip_address=``, ``network?contains_address=``, ``ipv4address?network=``,
``range?network=``, ``fixedaddress?network=`` and the IPv6 twins) is answered for the default view only.
So a lookup that wants every view sends such a request once for each view and joins the answers.

``utils.api`` imports this module, so this module imports ``utils.api`` only inside functions.
"""
from __future__ import annotations

import argparse
import contextlib
import json
from dataclasses import dataclass, field, replace
from typing import (
    TYPE_CHECKING, Any, Callable, Dict, Hashable, Iterable, List, Mapping, Optional, Sequence, Set, Tuple, TypeVar,
)
from urllib.parse import quote

from cn_tool.core.base import ScriptContext

if TYPE_CHECKING:
    from concurrent.futures import Executor

    from cn_tool.utils.api import InfobloxResult

# Row keys of the view column. The JSON name of the first two is ``network_view``, of DNS_VIEW ``dns_view``.
NETWORK_VIEW = "network view"  # site, subnet detail, child-container and warnings rows
NETWORK_VIEW_TITLE = "Network view"  # ip rows and the subnet summary
DNS_VIEW = "DNS view"  # fqdn rows

# The one discovery request: the grid's network views and the DNS views each one holds.
NETWORK_VIEWS_URI = "networkview?_return_fields=name,is_default,associated_dns_views"
VIEW_LIST_LIMIT = 10  # network views a lookup's message names; ``cn doctor`` names every one

RequestFn = Callable[..., "InfobloxResult"]  # utils.api.request_result, or a module's own name for it


def parse_view_name(text: str) -> str:
    """The network view name ``--view`` was given, stripped; a blank name is an error (argparse reports it)."""
    name = str(text).strip()
    if not name:
        raise ValueError("NAME must not be empty")
    return name


def configured_view(ctx: ScriptContext) -> str:
    """The network view ``[api] network_view`` names, stripped; "" (every view) when it is unset."""
    return str(ctx.cfg.get("api_network_view") or "").strip()


def scope_network(uri: str, network_view: str) -> str:
    """``uri`` limited to one network view (``&network_view=``); unchanged for "" (every view)."""
    return f"{uri}&network_view={quote(network_view, safe='')}" if network_view else uri


def scope_dns(uri: str, dns_view: str) -> str:
    """``uri`` limited to one DNS view (``&view=``), for the DNS record searches; unchanged for ""."""
    return f"{uri}&view={quote(dns_view, safe='')}" if dns_view else uri


Key = TypeVar("Key", bound=Hashable)


def scoped_uris(uri: str, views: Sequence[str]) -> List[Tuple[str, str]]:
    """
    ``(view, uri)`` for each of ``views``: ``uri`` limited to that view, in the order given. Without
    views it is ``[("", uri)]``, the request unchanged (the byte-identical single request of a grid
    with one view, or of a grid whose views could not be listed).
    """
    if not views:
        return [("", uri)]
    return [(view, scope_network(uri, view)) for view in views]


def request_in_views(
    ctx: ScriptContext,
    uris: Mapping[Key, str],
    views: Sequence[str],
    *,
    request_fn: Optional[RequestFn] = None,
    paged: bool = False,
    executor: Optional[Executor] = None,
) -> Dict[Key, List[Tuple[str, InfobloxResult]]]:
    """
    Send every request of ``uris`` (a key for each WAPI path) once for each view of ``views``, and return
    the answers by key: ``[(view, result)]`` in the order of ``views``. Without views each request is sent
    once, as it is, and its view is "".

    The requests run on ``executor`` when the caller gives one, else on a pool of their own bounded by
    ``[api] max_workers``. A caller that already runs in a pool of its own (``cn subnet`` resolving many
    addresses) passes one request pool that all its workers share, so the pools do not multiply into
    W x W threads; a worker that waits on this call must not itself be a thread of ``executor``. The
    ceiling on requests in flight is held by the client (``api._InFlightLimiter``), not by the pools.

    This is the one place that asks the views one by one, for the requests the WAPI answers for the default
    view when they name none (see the module text). ``request_fn`` is the module's own name for
    ``request_result`` (None: ``utils.api.request_result``); a request is sent with ``ensure_auth=False``,
    because a lookup has logged in already, and with ``paged=True`` only when ``paged`` is set.
    """
    if not uris:
        return {}

    from concurrent.futures import ThreadPoolExecutor

    from cn_tool.utils import api  # here, not at the top: utils.api imports this module

    send = api.request_result if request_fn is None else request_fn
    options: Dict[str, Any] = {"paged": True} if paged else {}
    jobs = [(key, view, uri) for key, base in uris.items() for view, uri in scoped_uris(base, views)]
    if len(jobs) == 1:  # one request needs no pool: the calling thread sends it, as it always did
        results = [send(ctx, jobs[0][2], ensure_auth=False, **options)]
    else:
        pool = (
            contextlib.nullcontext(executor) if executor is not None
            else ThreadPoolExecutor(max_workers=api.bound_infoblox_workers(ctx, len(jobs)))
        )
        with pool as running:
            futures = [running.submit(send, ctx, uri, ensure_auth=False, **options) for _, _, uri in jobs]
            results = [future.result() for future in futures]
    answers: Dict[Key, List[Tuple[str, InfobloxResult]]] = {key: [] for key in uris}
    for (key, view, _), result in zip(jobs, results):
        answers[key].append((view, result))
    return answers


def _items_of(result: InfobloxResult) -> List[Dict[str, Any]]:
    """The items of an answer: ``items``, else the list its ``content`` holds (a fake carries only the bytes)."""
    if result.items:
        return list(result.items)
    try:
        payload = json.loads(result.content)
    except (TypeError, ValueError):
        return []
    return [item for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []


def merge_view_results(results: Sequence[InfobloxResult]) -> InfobloxResult:
    """
    The answers of one request asked in several views, as the one answer a single unscoped request would
    have given if the grid searched every view. ``results`` is not empty, in view order.

    - Any failure (anything but a hit or a miss) is the merge's failure: the first one, in view order.
    - Otherwise the items of every answered view are joined, in view order, with the content to match; a
      view that missed (the grid's 400 "no network holds the address", or a 404) contributes nothing, and
      the merge is truncated when any view was.
    - It is a miss only when every view missed. It then is a record miss (not "no network holds the
      address") as soon as one view said so, because a network holds the address somewhere.

    A single result is returned as it is, so a grid with one view sees the very result of its request.
    """
    if len(results) == 1:
        return results[0]
    failure = next((result for result in results if result.failed), None)
    if failure is not None:
        return failure
    answered = [result for result in results if result.ok]
    if not answered:
        return next((result for result in results if not result.no_network), results[0])
    items = [item for result in answered for item in _items_of(result)]
    return replace(
        answered[0], items=items, content=json.dumps(items).encode(), truncated=any(r.truncated for r in answered)
    )


def present_rows(
    rows: Iterable[Mapping[str, Any]],
    key: str,
    show: bool,
    *,
    fallback: str = "",
    before: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Copies of ``rows`` with the view column ``key`` shown or hidden; the input rows are not changed.

    With ``show`` false the column is dropped. With ``show`` true a row that has ``key`` keeps it in
    place (an empty value becomes ``fallback``), and a row without it gets ``key`` = ``fallback``
    inserted before the column ``before`` (first when ``before`` is None; last when the row has no
    such column).
    """
    presented: List[Dict[str, Any]] = []
    for row in rows:
        if not show:
            presented.append({name: value for name, value in row.items() if name != key})
        elif key in row:
            presented.append({
                name: (value if str(value or "").strip() else fallback) if name == key else value
                for name, value in row.items()
            })
        else:
            new_row: Dict[str, Any] = {}
            if before is None:
                new_row[key] = fallback
            for name, value in row.items():
                if name == before:
                    new_row[key] = fallback
                new_row[name] = value
            new_row.setdefault(key, fallback)
            presented.append(new_row)
    return presented


_CONFIGURED = "[api] network_view"  # the ``source`` of a view the setting chose
_NO_ENDPOINT = "Infoblox API endpoint is not configured."
_NO_VIEWS = "the grid lists no network view to this account"


@dataclass(frozen=True)
class GridViews:
    """The network views of the grid, as one discovery request listed them."""

    names: Tuple[str, ...] = ()  # network views, in the grid's order
    default: str = ""  # the one flagged ``is_default``
    dns: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)  # network view -> its DNS views
    error: str = ""  # why the views could not be listed; "" when they were listed

    def owner(self, dns_view: str) -> str:
        """The network view that holds the DNS view ``dns_view``; "" when no network view lists it."""
        for network_view, dns_views in self.dns.items():
            if dns_view in dns_views:
                return network_view
        return ""

    @property
    def dns_view_count(self) -> int:
        """How many distinct DNS views the network views hold between them."""
        return len({dns_view for dns_views in self.dns.values() for dns_view in dns_views})


@dataclass(frozen=True)
class ViewProblem:
    """Why a lookup cannot go ahead with the requested view."""

    exit_code: int  # 2: no such view; 3: the views could not be listed, or none is listed
    message: str  # the user-facing text, without the "cn <command>: " prefix


def _named(labels: Iterable[Any]) -> Set[str]:
    """The distinct, non-blank labels of ``labels`` (a row's view may be missing or empty)."""
    cleaned = (str(label or "").strip() for label in labels)
    return {label for label in cleaned if label}


class ViewScope:
    """
    The network view one lookup searches, and the decisions that depend on it. Built per run by
    ``view_scope``; call it from the module's main thread only (before a thread pool starts or after
    it ends).

    ``requested`` is the view to search ("" searches every view) and ``source`` says where it came
    from (``--view``, ``--all-views``, ``[api] network_view`` or ""), so a message can always say why
    a lookup was scoped. ``json`` tells that the run renders JSON.

    The grid's views are read lazily, at most once per run, and only when the answer matters: a
    requested view must exist, a lookup with no requested view that must ask each view (``all_views``)
    needs the list, or the rows carry views and the number of views decides whether the view column
    shows. For a lookup that asks each view only for the column (``site``, ``fqdn``), unlabelled answers
    without a requested view never trigger the request.
    """

    def __init__(
        self,
        ctx: ScriptContext,
        requested: str = "",
        source: str = "",
        *,
        json: bool = False,
        request_fn: Optional[RequestFn] = None,
    ) -> None:
        self._ctx = ctx
        self.requested = requested
        self.source = source
        self.json = json
        self._request_fn = request_fn  # None: utils.api.request_result, looked up when it is called
        self._grid: Optional[GridViews] = None
        self._fallback_logged = False  # all_views() said once that it fell back to the default view

    # -- the grid ------------------------------------------------------------------------------------

    def grid(self) -> GridViews:
        """The grid's views: one request on first use, kept for the run (a failure too, never retried)."""
        if self._grid is None:
            self._grid = self._read_grid()
            if self._grid.error and not self.requested:
                self._ctx.logger.warning(
                    "Network views could not be listed (%s); the view column is shown.", self._grid.error.rstrip(".")
                )
        return self._grid

    def _read_grid(self) -> GridViews:
        """Ask the grid for its network views; without an endpoint nothing is sent."""
        endpoint = str(self._ctx.cfg.get("api_endpoint") or "").strip()
        if not endpoint or endpoint == "API_URL":
            return GridViews(error=_NO_ENDPOINT)

        from cn_tool.utils import api  # here, not at the top: utils.api imports this module

        request_fn = api.request_result if self._request_fn is None else self._request_fn
        result = request_fn(self._ctx, NETWORK_VIEWS_URI, ensure_auth=False)
        if result.failed:
            return GridViews(error=api.describe_infoblox_failure(result))
        items = [item for item in result.items if item.get("name")]
        if not items:
            return GridViews(error=_NO_VIEWS)
        return GridViews(
            names=tuple(str(item["name"]) for item in items),
            default=next((str(item["name"]) for item in items if item.get("is_default")), ""),
            dns={
                str(item["name"]): tuple(str(view) for view in item.get("associated_dns_views") or ())
                for item in items
            },
        )

    def problem(self, *, for_doctor: bool = False) -> Optional[ViewProblem]:
        """
        What stops a lookup from using the requested view; None when nothing is requested (no request
        is sent) or the view is on the grid. A lookup names at most ``VIEW_LIST_LIMIT`` views and tells
        the user to run ``cn doctor``; the doctor itself (``for_doctor``) names every view.
        """
        if not self.requested:
            return None
        grid = self.grid()
        if grid.error:
            tail = "" if for_doctor else "; check with: cn doctor"
            reason = grid.error.rstrip(".")
            return ViewProblem(3, f"cannot check network view '{self.requested}' ({self.source}): {reason}{tail}")
        if self.requested in grid.names:
            return None
        return ViewProblem(2, self._unknown_view(grid, for_doctor))

    def _unknown_view(self, grid: GridViews, for_doctor: bool) -> str:
        """The message for a requested view that is not a network view of the grid."""
        configured = self.source == _CONFIGURED
        owner = grid.owner(self.requested)
        if owner:  # the name of a DNS view: point at the network view that holds it
            hint = f"set {_CONFIGURED} = {owner}" if configured else f"use --view {owner}"
            return (
                f"'{self.requested}' is a DNS view of network view '{owner}', "
                f"not a network view ({self.source}); {hint}"
            )
        shown = grid.names if for_doctor else grid.names[:VIEW_LIST_LIMIT]
        listing = ", ".join(shown)
        if len(shown) < len(grid.names):
            listing += f" and {len(grid.names) - len(shown)} more (cn doctor lists them all)"
        message = f"no network view '{self.requested}' on the grid ({self.source}); network views: {listing}"
        if configured:
            message += "; correct the setting, or leave it empty to search every view"
        lookalike = next((name for name in grid.names if name.lower() == self.requested.lower()), "")
        if lookalike:
            message += f"; did you mean '{lookalike}'?"
        return message

    def dns_views(self) -> Tuple[str, ...]:
        """The DNS views of the requested network view, in the grid's order; () when every view is searched."""
        if not self.requested:
            return ()
        return tuple(self.grid().dns.get(self.requested, ()))

    def all_views(self) -> Tuple[str, ...]:
        """
        The network views to ask, one request each, for the requests the WAPI answers for the default view
        when they name none (``request_in_views``): every view of the grid in name order when none is
        requested and the grid has more than one. () otherwise, and then a lookup sends its request as it
        always did: a requested view is applied by the caller (one scoped request), a grid with one view
        needs no argument, and a grid whose views cannot be listed is searched in its default view only
        (logged once), which is what such a lookup did before.

        The first call may read the grid's views (one request, kept for the run), so call it from the main
        thread, after the login.
        """
        if self.requested:
            return ()
        grid = self.grid()
        if grid.error:
            if not self._fallback_logged:
                self._fallback_logged = True
                self._ctx.logger.warning("Without the list of network views a lookup searches the default network view only.")
            return ()
        return tuple(sorted(grid.names)) if len(grid.names) > 1 else ()

    # -- the view column -----------------------------------------------------------------------------

    def column(self, labels: Iterable[Any], *, dns: bool = False) -> bool:
        """
        Whether a table, markdown, CSV or xlsx output shows the view column. One decision per run,
        over every row, whatever the rows are: it shows when a view was requested; when the labels
        name more than one view; or when the grid has more than one view (``dns``: more than one DNS
        view) or its views could not be listed. Blank labels are ignored.
        """
        if self.requested:
            return True
        named = _named(labels)
        if not named:
            return False
        if len(named) > 1:
            return True
        grid = self.grid()
        if grid.error:
            return True
        return (grid.dns_view_count if dns else len(grid.names)) > 1

    def result_column(self, labels: Iterable[Any], *, dns: bool = False) -> bool:
        """
        Whether the rows handed back to the renderer carry the view: JSON always does when a row has a label,
        and for ``dns`` (``fqdn``) without one too, because an IPAM-only host record has no DNS view and its
        row says so with an empty ``dns_view``, like the rows of the other records.
        """
        named = _named(labels)
        if self.json and (named or dns):
            return True
        return self.column(named, dns=dns)

    # -- texts ---------------------------------------------------------------------------------------

    @property
    def where(self) -> str:
        """" in network view prod" for a requested view, else ""."""
        return f" in network view {self.requested}" if self.requested else ""

    def scoped(self, text: str) -> str:
        """``text`` with ``where`` before its closing period, or appended; unchanged when every view is searched."""
        where = self.where
        if not where:
            return text
        if text.endswith("."):
            return f"{text[:-1]}{where}."
        return f"{text}{where}"

    def banner(self, *, dns: bool = False) -> str:
        """The menu header naming the view the lookup searches; "" when every view is searched."""
        if not self.requested:
            return ""
        detail = self.source
        if dns:
            views = self.dns_views()
            detail += f"; DNS views {', '.join(views)}" if views else "; no DNS view"
        return f"Network view: {self.requested} ({detail}); other network views are not searched."


def view_scope(
    ctx: ScriptContext,
    args: Optional[argparse.Namespace] = None,
    request_fn: Optional[RequestFn] = None,
) -> ViewScope:
    """
    The ``ViewScope`` of one run. ``--view NAME`` beats ``--all-views``, which beats ``[api] network_view``,
    which beats searching every view. ``request_fn`` is the module's own name for ``request_result``, so
    the discovery request reaches the same fake in a test; None uses ``utils.api.request_result``.

    ``args.format`` is read here, once: it is the only format check in the whole feature.
    """
    view = getattr(args, "view", None)
    if view is None:
        requested = configured_view(ctx)
        source = _CONFIGURED if requested else ""
    elif view == "":
        requested, source = "", "--all-views"
    else:
        requested, source = view, "--view"
    return ViewScope(
        ctx, requested, source, json=getattr(args, "format", None) == "json", request_fn=request_fn
    )
