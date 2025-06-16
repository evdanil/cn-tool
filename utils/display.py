from itertools import cycle
from typing import Dict, List, Union, Any, Optional
from rich.console import Console, Group
from rich.style import Style
from rich.theme import Theme
from rich.table import Table
from rich import box
from rich.box import Box
from rich.panel import Panel
from .color_schemes import COLOR_SCHEMES
from core.base import ScriptContext


class ThemedConsole:
    def __init__(self, color_scheme: str = "default") -> None:
        self.console: Console
        self.theme: Theme
        self.color_scheme: str
        self.colors: Dict[str, str]
        self.set_color_scheme(color_scheme)

    def set_color_scheme(self, color_scheme: str) -> None:
        if color_scheme not in COLOR_SCHEMES:
            print(f"Warning: Unknown color scheme '{color_scheme}'. Using default.")
            color_scheme = "default"

        self.color_scheme = color_scheme
        self.colors = COLOR_SCHEMES[color_scheme]

        # Create a custom theme that maps all color names to our scheme
        theme_styles: Dict[str, Style] = {}
        for color in ["red", "green", "yellow", "blue", "magenta", "cyan", "white"]:
            theme_styles[color] = Style(color=self.colors.get(color, color))

        # Add special styles
        theme_styles["bold"] = Style(bold=True)

        self.theme = Theme(theme_styles)
        self.console = Console(theme=self.theme)

    def print(self, *objects: Any, sep: str = " ", end: str = "\n", style: Optional[Union[str, Style]] = None, **kwargs: Any) -> None:
        if isinstance(style, str):
            style = self.colors.get(style, style)
        self.console.print(*objects, sep=sep, end=end, style=style, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.console, name)


console = ThemedConsole()


def get_global_color_scheme(cfg: Dict[str, Any]) -> Dict[str, str]:
    color_scheme = cfg.get("theme_name", "default")
    return COLOR_SCHEMES.get(color_scheme, COLOR_SCHEMES["default"])


def set_global_color_scheme(ctx: ScriptContext) -> None:
    ctx.console.set_color_scheme(ctx.cfg.get("theme_name", "default"))


def print_search_config_data(ctx: ScriptContext, data: List[List[Any]]) -> None:
    """
    Prints the configuration search data in a formatted manner.
    Sort the data array based on the device name and line number, then prints out data per device.
    Columns in the data are as follows:
    [ip(search ip matching), device_name(str), line_num(int), config_line(str)]

    @param data(list[list]): config data to print out
    """

    if not data:
        # Nothing to print
        return

    console = ctx.console
    color_scheme = ctx.cfg.get("theme_name", "default")

    colors = COLOR_SCHEMES.get(color_scheme, COLOR_SCHEMES["default"])
    data.sort(key=lambda x: (x[1], x[2]))

    current_device = ""
    current_line = 0

    for row in data:
        device, line_number, line = row[1].upper(), int(row[2]), row[3]
        if device != current_device:
            current_device = device
            current_line = line_number
            console.print(f"\n[{colors['title']}]Device {current_device}[/]:", highlight=False)
            console.print(f"[{colors['header']}]Line {current_line}:[/]", highlight=False)
        elif line_number - current_line >= 100:
            current_line = line_number

            console.print(f"\n[{colors['header']}]Line {current_line}:[/]", highlight=False)

        console.print(f"[{colors['value']}]{line}[/]", highlight=False)
    console.print("\n")


def print_multi_table_panel(ctx: ScriptContext, tables: List[Union[Table, Panel]], title: str) -> None:

    color_scheme = ctx.cfg.get("theme_name", "default")
    colors = COLOR_SCHEMES.get(color_scheme, COLOR_SCHEMES["default"])

    group = Group(*tables)
    panel = Panel(group, title=title, border_style=colors["title"], title_align="left", padding=1, expand=False)
    ctx.console.print(panel)


def create_show_version_table(data: Dict[str, Any], hostname: str, color_scheme: str = "default") -> Optional[Table]:
    if color_scheme not in COLOR_SCHEMES:
        color_scheme = "default"
    colors = COLOR_SCHEMES[color_scheme]

    if not data:
        return None

    table = Table(title="General Information", show_header=True, header_style=colors["header"], box=box.MINIMAL, title_justify="left")
    table.add_column("Hostname", style=colors["hostname"])
    table.add_column("Serial", style=colors["sn"])
    table.add_column("Uptime", style=colors["date"])
    table.add_column("Software Version", style=colors["license_type"])
    table.add_column("Software Image", style=colors["description"], overflow='fold')

    table.add_row(
        hostname.upper(),
        data.get("Serial Number", 'N/A'),
        data.get("Uptime", 'N/A'),
        data.get("Software Version", 'N/A'),
        data.get("Software Image", 'N/A')
    )
    return table


def create_device_error_table(hostname: str, reason: str, color_scheme: str = "default") -> Optional[Table]:
    if color_scheme not in COLOR_SCHEMES:
        color_scheme = "default"
    colors = COLOR_SCHEMES[color_scheme]

    table = Table(title="General Information", show_header=True, header_style=colors["header"], box=box.MINIMAL, title_justify="left")
    table.add_column("Hostname", style=colors["hostname"])
    table.add_column("Status", style=colors["sn"])
    table.add_column("Reason", style=colors["sn"])

    table.add_row(
        hostname.upper(),
        "Unable to access device",
        reason
    )
    return table


def create_show_license_table(data: List[Dict[str, str]], hostname: str, color_scheme: str = "default") -> Optional[Table]:
    if color_scheme not in COLOR_SCHEMES:
        color_scheme = "default"
    colors = COLOR_SCHEMES[color_scheme]

    if not data:
        return None

    table = Table(title="License Information", show_header=True, header_style=colors["header"], box=box.MINIMAL, title_justify="left")
    table.add_column("Feature", style=colors["feature"])
    table.add_column("Attribute", style=colors["feature"])
    table.add_column("Value", style=colors["value"])

    for feature in data:
        table.add_row(feature.get('Feature', 'N/A'), '', '')
        for key, value in feature.items():
            if key not in ['Index', 'Feature']:
                table.add_row('', key, value)
    return table


def create_license_summary_table(data: List[Dict[str, str]], hostname: str, color_scheme: str = "default") -> Optional[Table]:
    if color_scheme not in COLOR_SCHEMES:
        color_scheme = "default"
    colors = COLOR_SCHEMES[color_scheme]

    if not data:
        return None

    if 'Index' in data[0]:
        # looks like an old device calling standard create_show_license_table
        return create_show_license_table(data, hostname, color_scheme)

    table = Table(title="License Summary", show_header=True, header_style=colors["header"], box=box.MINIMAL, title_justify="left")
    table.add_column("License", style=colors["license"])
    table.add_column("Entitlement Tag", style=colors["tag"])
    table.add_column("Count", style=colors["count"])
    table.add_column("Status", style=colors["status"])

    for license_item in data:
        table.add_row(
            license_item['License'],
            license_item['Entitlement Tag'],
            license_item['Count'],
            license_item['Status']
        )
    return table


def create_license_reservation_tables(data: Dict[str, Dict[str, Any]], hostname: str, color_scheme: str = "default") -> Optional[List[Table]]:
    if color_scheme not in COLOR_SCHEMES:
        color_scheme = "default"
    colors = COLOR_SCHEMES[color_scheme]

    if not data:
        return None

    all_tables: List[Table] = []
    license_reservation = "UNKNOWN"
    # Create and print the device information table
    device_table = Table(title="Overall License Information", show_header=True, header_style=colors["title"], box=box.MINIMAL, title_justify="left")
    device_table.add_column("Hostname", style=colors["hostname"], no_wrap=True)
    device_table.add_column("Serial Number", style=colors["sn"], no_wrap=True)
    device_table.add_column("Type", style=colors["type"])
    device_table.add_column("PID", style=colors["pid"])
    device_table.add_column("Reservation Status", style=colors["status"])
    device_table.add_column("Reservation Date", style=colors["date"])
    device_table.add_column("Export Controlled", style=colors["export"])
    device_table.add_column("Confirmation Code", style=colors["code"])
    device_table.add_column("License Reservation", style=colors["reserved"])

    for sn, info in data.items():
        device_table.add_row(
            hostname.upper(),
            sn,
            info.get('TYPE', 'N/A'),
            info.get('PID', 'N/A'),
            info.get('RESERVATION_STATUS', 'N/A'),
            info.get('RESERVATION_DATE', 'N/A'),
            info.get('EXPORT_CONTROLLED', 'N/A'),
            info.get('CONFIRMATION_CODE', 'N/A'),
            info.get('LICENSE_RESERVATION', license_reservation)
        )
    all_tables.append(device_table)

    # Create and print a license table for each device
    license_table = Table(title="Extended License Information", show_header=True, header_style=colors["title"], box=box.MINIMAL, title_justify="left")
    license_table.add_column("Serial", style=colors["sn"], no_wrap=True)
    license_table.add_column("Type", style=colors["license_type"], no_wrap=True)
    license_table.add_column("License Name", style=colors["license_name"], no_wrap=True)
    license_table.add_column("Full Name", style=colors["license_full"])
    license_table.add_column("Description", style=colors["description"])
    license_table.add_column("Total Reserved", style=colors["reserved"])
    license_table.add_column("Enforcement Type", style=colors["enforcement"])
    license_table.add_column("Authorization Type", style=colors["auth_type"])
    license_table.add_column("License Type", style=colors["license_type"])
    license_table.add_column("Start Date", style=colors["start_date"])
    license_table.add_column("End Date", style=colors["end_date"])
    license_table.add_column("Term Count", style=colors["term_count"])
    for sn, info in data.items():
        for license_item in info.get('LICENSES', []):
            license_table.add_row(
                sn,
                info.get('TYPE', 'N/A'),
                license_item.get('LICENSE_NAME', 'N/A'),
                license_item.get('LICENSE_FULL_NAME', 'N/A'),
                license_item.get('LICENSE_DESCRIPTION', 'N/A'),
                license_item.get('TOTAL_RESERVED', 'N/A'),
                license_item.get('ENFORCEMENT_TYPE', 'N/A'),
                license_item.get('AUTHORIZATION_TYPE', 'N/A'),
                license_item.get('LICENSE_TYPE', 'N/A'),
                license_item.get('START_DATE', 'N/A'),
                license_item.get('END_DATE', 'N/A'),
                license_item.get('TERM_COUNT', 'N/A')
            )

    if license_table.row_count > 0:
        all_tables.append(license_table)

    return all_tables if all_tables else None


def create_table(
    ctx: ScriptContext,
    title: str,
    columns: List[str],
    data: List[List[Any]],
    title_style: str = "bold yellow",
    box_style: Box = box.MINIMAL,
    **kwargs: Any
) -> Table:
    """
    Creates a Rich table with the provided parameters.
    @param    logger(Logger): logger instance.
    @param    title (str): The title of the table.
    @param    columns (list[str]): A list of column names.
    @param    data (list[list]): A list of rows, where each row is a list of data values.
    @param    color_scheme (str, optional): The color scheme to use. Defaults to "default".
    @param    title_style (str, optional): The style for the table title. Defaults to "bold yellow".
    @param    box (box, optional): The box style for the table. Defaults to box.MINIMAL.

    @return    Table: The created Rich table.

    """
    logger = ctx.logger
    color_scheme = ctx.cfg.get("theme_name", "default")
    colors = COLOR_SCHEMES.get(color_scheme, COLOR_SCHEMES["default"])

    title = title.upper()
    logger.debug(f"Table - title = {title} columns = {len(columns)} rows = {len(data)}")

    color_cycle = cycle(colors.values())

    table = Table(title=title, title_style=colors.get("title", title_style), box=box_style, **kwargs)
    for column in columns:
        table.add_column(
            column, justify="left", style=next(color_cycle, next(color_cycle)), no_wrap=False
        )

    for row in data:
        table.add_row(*[str(item) for item in row])

    return table


def print_table_data(
    ctx: ScriptContext, data: Dict[str, List[Dict[str, Any]]], prefix: Dict[str, str] = {}, suffix: Dict[str, str] = {}
) -> None:
    """
    Prints data using keys as column names, can use prefix/suffix dictionary to add additional information to title (main keys)
    keys in data should match keys in suffix/prefix
    """
    if not data:
        ctx.console.print("No data to display")
        return

    tables: List[Union[Table, Panel]] = []
    for key, value_list in data.items():
        if not value_list:
            continue

        section_title = key
        prefix_text = prefix.get(key, "")
        suffix_text = suffix.get(key, "")
        section_title = f"{prefix_text} {section_title} {suffix_text}".strip()
        section_title = section_title.upper()

        columns = list(value_list[0].keys())
        table_data = [[item for item in record.values()] for record in value_list]

        tables.append(create_table(ctx, section_title, columns, table_data, title_justify="left"))

    if tables:
        print_multi_table_panel(ctx, tables, '')
