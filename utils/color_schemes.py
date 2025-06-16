from typing import Dict

COLOR_SCHEMES: Dict[str, Dict[str, str]] = {
    "default": {
        "title": "bold #FF69B4",  # Hot Pink
        "header": "bold #00CED1",  # Dark Turquoise
        "hostname": "#20B2AA",  # Light Sea Green
        "sn": "#32CD32",  # Lime Green
        "type": "#4169E1",  # Royal Blue
        "pid": "#FFD700",  # Gold
        "status": "#DA70D6",  # Orchid
        "date": "#40E0D0",  # Turquoise
        "export": "#FF6347",  # Tomato
        "code": "#3CB371",  # Medium Sea Green
        "license_name": "#1E90FF",  # Dodger Blue
        "license_full": "#00FFFF",  # Cyan
        "description": "#F0E68C",  # Khaki
        "reserved": "#DDA0DD",  # Plum
        "enforcement": "#DC143C",  # Crimson
        "auth_type": "#2E8B57",  # Sea Green
        "license_type": "#4682B4",  # Steel Blue
        "start_date": "#5F9EA0",  # Cadet Blue
        "end_date": "#BDB76B",  # Dark Khaki
        "term_count": "#BA55D3",  # Medium Orchid
        "license": "#228B22",  # Forest Green
        "tag": "#DAA520",  # Goldenrod
        "count": "#0000CD",  # Medium Blue
        "feature": "#48D1CC",  # Medium Turquoise
        "value": "#F4A460",  # Sandy Brown
        "success": "#2E8B57",  # Sea Green
        "warning": "#FFA500",  # Orange
        "error": "#B22222",  # Firebrick
        "info": "#4682B4",  # Steel Blue
        "default": "#D2691E",  # Chocolate
        "red": "#DC143C",  # Crimson
        "green": "#228B22",  # Forest Green
        "yellow": "#FFD700",  # Gold
        "blue": "#4169E1",  # Royal Blue
        "magenta": "#FF00FF",  # Magenta
        "cyan": "#00CED1",  # Dark Turquoise
        "white": "#F0F8FF",  # Alice Blue
        "bold": "bold"
    },
    "monochrome": {
        "title": "bold #FFFFFF",  # Pure White
        "header": "bold #E0E0E0",  # Light Gray
        "hostname": "#D3D3D3",  # Light Gray
        "sn": "#C0C0C0",  # Silver
        "type": "#A9A9A9",  # Dark Gray
        "pid": "#DCDCDC",  # Gainsboro
        "status": "#F5F5F5",  # White Smoke
        "date": "#E8E8E8",
        "export": "#B8B8B8",
        "code": "#D9D9D9",
        "license_name": "#CFCFCF",
        "license_full": "#EBEBEB",
        "description": "#C8C8C8",
        "reserved": "#DBDBDB",
        "enforcement": "#BDBDBD",
        "auth_type": "#DEDEDE",
        "license_type": "#E3E3E3",
        "start_date": "#F0F0F0",
        "end_date": "#F8F8F8",
        "term_count": "#E6E6E6",
        "license": "#D6D6D6",
        "tag": "#CCCCCC",
        "count": "#EFEFEF",
        "feature": "#FAFAFA",
        "value": "#F2F2F2",
        "success": "#EAEAEA",
        "warning": "#DFDFDF",
        "error": "#C6C6C6",
        "info": "#EDEDED",
        "default": "#D0D0D0",
        "red": "#B0B0B0",
        "green": "#BEBEBE",
        "yellow": "#CDCDCD",
        "blue": "#DADADA",
        "magenta": "#E9E9E9",
        "cyan": "#F7F7F7",
        "white": "#FFFFFF",  # Pure White
        "bold": "bold"
    },
    "pastel": {
        "title": "bold #87CEFA",  # Light Sky Blue
        "header": "bold #98FB98",  # Pale Green
        "hostname": "#DDA0DD",  # Plum
        "sn": "#90EE90",  # Light Green
        "type": "#ADD8E6",  # Light Blue
        "pid": "#F0E68C",  # Khaki
        "status": "#E0FFFF",  # Light Cyan
        "date": "#FFB6C1",  # Light Pink
        "export": "#FFA07A",  # Light Salmon
        "code": "#98FB98",  # Pale Green
        "license_name": "#87CEFA",  # Light Sky Blue
        "license_full": "#E0FFFF",  # Light Cyan
        "description": "#FAFAD2",  # Light Goldenrod Yellow
        "reserved": "#D8BFD8",  # Thistle
        "enforcement": "#FFA07A",  # Light Salmon
        "auth_type": "#90EE90",  # Light Green
        "license_type": "#ADD8E6",  # Light Blue
        "start_date": "#AFEEEE",  # Pale Turquoise
        "end_date": "#FFFACD",  # Lemon Chiffon
        "term_count": "#DDA0DD",  # Plum
        "license": "#98FB98",  # Pale Green
        "tag": "#F0E68C",  # Khaki
        "count": "#ADD8E6",  # Light Blue
        "feature": "#E0FFFF",  # Light Cyan
        "value": "#FFF5EE",  # Seashell
        "success": "#90EE90",  # Light Green
        "warning": "#FAFAD2",  # Light Goldenrod Yellow
        "error": "#FFA07A",  # Light Salmon
        "info": "#E6E6FA",  # Lavender
        "default": "#FFF5EE",  # Seashell
        "red": "#FFA07A",  # Light Salmon
        "green": "#98FB98",  # Pale Green
        "yellow": "#F0E68C",  # Khaki
        "blue": "#ADD8E6",  # Light Blue
        "magenta": "#DDA0DD",  # Plum
        "cyan": "#E0FFFF",  # Light Cyan
        "white": "#FFF5EE",  # Seashell
        "bold": "bold"
    },
    "dark": {
        "title": "bold #E0FFFF",  # Light Cyan
        "header": "bold #00CED1",  # Dark Turquoise
        "hostname": "#20B2AA",  # Light Sea Green
        "sn": "#32CD32",  # Lime Green
        "type": "#4169E1",  # Royal Blue
        "pid": "#DAA520",  # Goldenrod
        "status": "#9370DB",  # Medium Purple
        "date": "#40E0D0",  # Turquoise
        "export": "#B22222",  # Firebrick
        "code": "#2E8B57",  # Sea Green
        "license_name": "#4682B4",  # Steel Blue
        "license_full": "#008B8B",  # Dark Cyan
        "description": "#CD853F",  # Peru
        "reserved": "#8A2BE2",  # Blue Violet
        "enforcement": "#8B0000",  # Dark Red
        "auth_type": "#006400",  # Dark Green
        "license_type": "#00008B",  # Dark Blue
        "start_date": "#008080",  # Teal
        "end_date": "#BDB76B",  # Dark Khaki
        "term_count": "#9932CC",  # Dark Orchid
        "license": "#228B22",  # Forest Green
        "tag": "#B8860B",  # Dark Goldenrod
        "count": "#0000CD",  # Medium Blue
        "feature": "#20B2AA",  # Light Sea Green
        "value": "#A9A9A9",  # Dark Gray
        "success": "#3CB371",  # Medium Sea Green
        "warning": "#FF8C00",  # Dark Orange
        "error": "#DC143C",  # Crimson
        "info": "#4682B4",  # Steel Blue
        "default": "#D2691E",  # Chocolate
        "red": "#B22222",  # Firebrick
        "green": "#228B22",  # Forest Green
        "yellow": "#DAA520",  # Goldenrod
        "blue": "#4169E1",  # Royal Blue
        "magenta": "#8A2BE2",  # Blue Violet
        "cyan": "#008B8B",  # Dark Cyan
        "white": "#D3D3D3",  # Light Gray
        "bold": "bold"
    }
}
