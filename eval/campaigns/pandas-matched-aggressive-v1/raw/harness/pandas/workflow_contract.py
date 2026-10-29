"""Preserve the user's task across lossy routing and JSON chart transport."""

import base64
import json
import math
import re
import struct

VERSION = "preserve-request-v5"
VERSIONS = {
    "preserve-request-v1",
    "preserve-request-v2",
    "preserve-request-v3",
    "preserve-request-v4",
    VERSION,
}

TASK_STEPS = """Perform only the analysis requested by the user, not generic data cleaning.
Preserve duplicate rows and missing values unless the requested operation explicitly changes them.
Compute the requested measure and return only the requested columns. Do not save files unless asked.
For a chart request, return its data table; leave plotting to the visualization stage.
"""

WRANGLING_STEPS = """Execute the requested analysis, not a generic data-cleaning pipeline.
Preserve duplicate rows and missing values unless the request explicitly asks to change them.
For aggregates, use exactly the requested operation and grouping columns. Count missing values
before any filling, and count duplicates before removing them. Return only requested columns.
Keep date labels in the requested format, including their year. When asked for all periods,
cover the observed date range, including periods whose measured values are all missing;
do not invent dates outside that range. For charts, return the table needed for the chart.
Do not generate a chart in the wrangling stage. Do not save files unless requested.
"""

AGGREGATION_RULES = """
For date periods, include the periods containing both endpoints, even when the first
observation is not on a period boundary. Construct period ranges from endpoint periods
(for example with PeriodIndex/period_range), not month-start date_range from a mid-month day.
For a requested total or sum, actually reduce the measure with sum after applying filters.
Without a requested grouping, this yields one aggregate row, not the filtered input rows.
Check the return statement implements the requested computation as well as the requested columns.
"""

PERIOD_AGGREGATION_RULES = """
For time-bucket aggregation, first derive a period key for EVERY original row from its date.
Group the original measure values by that derived key and apply the requested aggregate.
Only after aggregation, reindex the grouped result against the complete period range.
Use zero for newly introduced empty sum buckets, and missing/null for empty mean buckets.
Do not merge period keys or period-start timestamps with raw daily timestamps: that drops
non-boundary observations. Keep keys as periods until aggregation and reindexing finish;
format the resulting period labels only when constructing the final table.
"""


PERIOD_API_RULES = """
For temporal grouping, call the preinstalled aggregate_periods helper directly; no import needed.
Signature: aggregate_periods(data, date_column, value_column, operation="sum", frequency="M",
 bucket_column="period", result_column=None, label_format=None, complete=True).
It accepts a DataFrame or list of DataFrames; operations sum/mean/count/min/max; frequencies
D/W/M/Q/Y. It groups original rows, completes the observed period range, and formats labels.
Set bucket_column and result_column to the requested output column names. For YYYY-MM labels
use label_format="%Y-%m". Return its result directly. Do not merge or reindex it again.
"""


class RequestPreservingStage:
    """Delegate to the real upstream graph with the full original user request."""

    def __init__(self, graph, request, stage, version=VERSION):
        if stage not in {"wrangling", "visualization"}:
            raise ValueError("Unknown workflow stage")
        self.graph = graph
        self.request = request
        self.stage = stage
        if version not in VERSIONS:
            raise ValueError("Unsupported workflow contract")
        self.version = version

    def prepare(self, state):
        prepared = dict(state)
        prepared["user_instructions"] = self.request
        if self.stage == "wrangling":
            prepared["recommended_steps"] = WRANGLING_STEPS
            if self.version in {"preserve-request-v2", "preserve-request-v3"}:
                prepared["recommended_steps"] += AGGREGATION_RULES
            if self.version == "preserve-request-v3":
                prepared["recommended_steps"] += PERIOD_AGGREGATION_RULES
            if self.version in {"preserve-request-v4", VERSION}:
                prepared["recommended_steps"] = TASK_STEPS
                temporal_grouping = re.search(
                    r"\b(?:daily|weekly|monthly|quarterly|yearly|"
                    r"(?:by|per|each)\s+(?:calendar\s+)?(?:day|week|month|quarter|year))\b",
                    self.request,
                    re.IGNORECASE,
                )
                if temporal_grouping:
                    prepared["recommended_steps"] += (
                        PERIOD_API_RULES
                        if self.version == VERSION
                        else AGGREGATION_RULES + PERIOD_AGGREGATION_RULES
                    )
                elif not re.search(
                    r"\b(?:by|per|each|group(?:ed|ing)?)\b", self.request, re.IGNORECASE
                ):
                    prepared["recommended_steps"] += (
                        "A requested total, mean, or count without grouping is "
                        "one scalar aggregate. "
                        "Apply filters first, then reduce the measure to one row. Do not add date "
                        "grouping merely because a date filter is present.\n"
                    )
        else:
            prepared["user_instructions"] += (
                "\nThe input table already contains the requested analysis. Plot its exact "
                "values and labels; do not aggregate a second time or reinterpret formatted "
                "date strings as dates in a different year."
            )
        return prepared

    def invoke(self, state, *args, **kwargs):
        return self.graph.invoke(self.prepare(state), *args, **kwargs)

    async def ainvoke(self, state, *args, **kwargs):
        return await self.graph.ainvoke(self.prepare(state), *args, **kwargs)


def portable_plot(plot):
    """Expand Plotly numeric typed arrays without changing their values or labels.

    The installed Plotly serializer encodes native-endian numeric buffers with
    these eight dtype tags. This application serializes and decodes on the same
    host. Unsupported tags/shapes fail rather than guessing the representation.
    """
    if isinstance(plot, str):
        plot = json.loads(plot)
    formats = {
        "i1": "b",
        "u1": "B",
        "i2": "h",
        "u2": "H",
        "i4": "i",
        "u4": "I",
        "f4": "f",
        "f8": "d",
    }

    def convert(value):
        if isinstance(value, list):
            return [convert(item) for item in value]
        if not isinstance(value, dict):
            return value
        if "bdata" not in value or "dtype" not in value:
            return {key: convert(item) for key, item in value.items()}
        if set(value) - {"bdata", "dtype", "shape"} or value["dtype"] not in formats:
            raise ValueError("Unsupported Plotly typed array")
        data = base64.b64decode(value["bdata"], validate=True)
        fmt = "=" + formats[value["dtype"]]
        if len(data) % struct.calcsize(fmt):
            raise ValueError("Truncated Plotly typed array")
        values = [
            None if isinstance(item, float) and not math.isfinite(item) else item
            for (item,) in struct.iter_unpack(fmt, data)
        ]
        if "shape" in value:
            shape = [int(part.strip()) for part in value["shape"].split(",")]
            if not shape or len(shape) > 8 or min(shape) <= 0 or math.prod(shape) != len(values):
                raise ValueError("Invalid Plotly array shape")

            def reshape(offset, dimensions):
                if len(dimensions) == 1:
                    return values[offset : offset + dimensions[0]]
                stride = math.prod(dimensions[1:])
                return [reshape(offset + i * stride, dimensions[1:]) for i in range(dimensions[0])]

            return reshape(0, shape)
        return values

    return convert(plot)
