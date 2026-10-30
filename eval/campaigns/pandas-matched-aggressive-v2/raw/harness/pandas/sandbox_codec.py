"""Versioned common A/B/C repair for nested Pandas sandbox results."""

import ast
import inspect

VERSION = "recursive-json-v2"
VERSIONS = {"recursive-json-v1", VERSION}


def _to_jsonable(obj, allow_periods=True):
    import datetime
    import json
    import math

    import numpy as np
    import pandas as pd

    if obj is None or obj is pd.NA or obj is pd.NaT:
        return None
    if allow_periods and isinstance(obj, pd.Period):
        return str(obj)
    if isinstance(obj, pd.DataFrame | pd.Series):
        return _to_jsonable(obj.to_dict(), allow_periods)
    if isinstance(obj, dict):
        result = {}
        for key, value in obj.items():
            key = _to_jsonable(key, allow_periods)
            if not isinstance(key, str | int | float | bool) and key is not None:
                raise TypeError("Unsupported JSON object key")
            # Match JSON's key conversion, and reject collisions rather than
            # silently dropping dataframe columns or index entries.
            key = next(iter(json.loads(json.dumps({key: None}, allow_nan=False))))
            if key in result:
                raise ValueError("JSON object key collision")
            result[key] = _to_jsonable(value, allow_periods)
        return result
    if isinstance(obj, list | tuple):
        return [_to_jsonable(value, allow_periods) for value in obj]
    if isinstance(obj, np.ndarray):
        return _to_jsonable(obj.tolist(), allow_periods)
    if isinstance(obj, datetime.datetime | datetime.date | datetime.time):
        return obj.isoformat()
    if isinstance(obj, np.generic):
        return _to_jsonable(obj.item(), allow_periods)
    if isinstance(obj, float) and not math.isfinite(obj):
        return None
    if isinstance(obj, str | int | float | bool):
        return obj
    raise TypeError(f"Unsupported sandbox result: {type(obj).__name__}")


def aggregate_periods(
    data,
    date_column,
    value_column,
    operation="sum",
    frequency="M",
    bucket_column="period",
    result_column=None,
    label_format=None,
    complete=True,
):
    """Aggregate observed rows before completing and formatting calendar buckets."""
    import pandas as pd

    if operation not in {"sum", "mean", "count", "min", "max"}:
        raise ValueError("Unsupported period aggregation")
    if frequency not in {"D", "W", "M", "Q", "Y"}:
        raise ValueError("Unsupported period frequency")
    result_column = value_column if result_column is None else result_column
    if bucket_column == result_column:
        raise ValueError("Bucket and result columns must differ")
    frame = pd.concat(data, ignore_index=True) if isinstance(data, list | tuple) else data
    dates = pd.to_datetime(frame[date_column], errors="raise")
    if dates.isna().any():
        raise ValueError("Period aggregation requires nonmissing dates")
    keys = dates.dt.to_period(frequency)
    values = pd.to_numeric(frame[value_column], errors="raise")
    grouped = values.groupby(keys, sort=True).agg(operation)
    if complete and len(keys):
        periods = pd.period_range(keys.min(), keys.max(), freq=frequency)
        grouped = grouped.reindex(
            periods, fill_value=0 if operation in {"sum", "count"} else float("nan")
        )
    result = grouped.rename_axis(bucket_column).reset_index(name=result_column)
    result[bucket_column] = (
        result[bucket_column].dt.strftime(label_format)
        if label_format is not None
        else result[bucket_column].astype(str)
    )
    return result


def repair_runner(source, version=VERSION, computation_api=None):
    """Replace only the known serializer; retain upstream execution restrictions."""
    if version not in VERSIONS:
        raise ValueError("Unsupported sandbox serialization version")
    tree = ast.parse(source)
    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_to_jsonable"
    ]
    if len(matches) != 1:
        raise ValueError("Unsupported upstream sandbox serializer layout")
    replacement = ast.parse(inspect.getsource(_to_jsonable)).body[0]
    replacement.args.defaults = [ast.Constant(version == VERSION)]
    tree.body[tree.body.index(matches[0])] = replacement
    if computation_api is not None:
        if computation_api != "period-aggregation-v1":
            raise ValueError("Unsupported computation API")
        assignments = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "exec_globals"
                for target in node.targets
            )
        ]
        if len(assignments) != 1 or not isinstance(assignments[0].value, ast.Dict):
            raise ValueError("Unsupported upstream execution globals layout")
        # Compile the helper in the SAME restricted namespace as generated code.
        # Its globals must never retain this adapter's unrestricted host imports.
        assignment = assignments[0]
        injection = ast.parse(
            "_primitive_globals = dict(exec_globals)\n"
            f"exec({inspect.getsource(aggregate_periods)!r}, _primitive_globals)\n"
            "exec_globals['aggregate_periods'] = _primitive_globals['aggregate_periods']"
        ).body
        for parent in ast.walk(tree):
            for _, value in ast.iter_fields(parent):
                if isinstance(value, list) and assignment in value:
                    index = value.index(assignment)
                    value[index + 1 : index + 1] = injection
    return ast.unparse(ast.fix_missing_locations(tree))
