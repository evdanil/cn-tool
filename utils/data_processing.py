
from typing import List, Any, Dict


def data_to_dict(column_names: List[str], data: List[List[Any]]) -> Dict[str, List[Any]]:
    """
    Converts a list of column names and corresponding data into a dictionary.

    @param column_names: List of column names.
    @param data: List of lists representing the data rows.
    @return: Dictionary with column names as keys and data as values.
    """
    # Function need two dimension array, in case if only single raw was sent it might be a simple list only

    result_dict: Dict[str, List[Any]] = {}

    if isinstance(data, list) and len(data) > 0:
        if not isinstance(data[0], list):
            data = [data]
    else:
        # if nothing to save or data is not list - return empty dict
        return result_dict

    # Iterate through column names
    for col_name in column_names:
        result_dict[col_name] = []

    # Iterate through data rows
    for row in data:
        # Iterate through column names and corresponding row data
        for col_name, col_data in zip(column_names, row):
            # Append data to the corresponding key in the dictionary
            result_dict[col_name].append(col_data)

    return result_dict


def remove_duplicate_rows_sorted_by_col(data: List[List[Any]], col: int) -> List[List[Any]]:
    """
    Removes duplicate rows from a list of lists, preserving order,
    and sorts the result by a specified column index.
    """
    seen = set()
    result = []
    for sublist in data:
        sublist_tuple = tuple(sublist)
        if sublist_tuple not in seen:
            seen.add(sublist_tuple)
            result.append(sublist)
    result.sort(key=lambda x: x[col])
    return result
