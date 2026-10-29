"""Typed worker-facing APIs for ordinary-demo resource monitors."""

from abc import ABC, abstractmethod

from langgraph.prebuilt.security.mediators.contracts import ResourceContract


class SQLDatabaseAPI(ABC):
    __slots__ = ()

    @abstractmethod
    def list_tables(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def schema(self, table_names: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def query(self, query: str) -> str:
        raise NotImplementedError


class RetrieverAPI(ABC):
    __slots__ = ()

    @abstractmethod
    def search(self, query: str) -> str:
        raise NotImplementedError


class SearchAPI(ABC):
    __slots__ = ()

    @abstractmethod
    def search(self, query: str) -> str:
        raise NotImplementedError


class TravelAPI(ABC):
    __slots__ = ()

    @abstractmethod
    def fetch_user(self, passenger_id: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def search_flights(self, criteria_json: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def update_ticket(self, ticket_no: str, new_flight_id: int, passenger_id: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def cancel_ticket(self, ticket_no: str, passenger_id: str) -> str:
        raise NotImplementedError


class PythonSessionAPI(ABC):
    __slots__ = ()

    @abstractmethod
    def execute(self, code: str) -> str:
        raise NotImplementedError


SQL_DATABASE = ResourceContract(
    SQLDatabaseAPI,
    class_name="sql_database",
    object_kind="database",
    lowering="demo.sqlite.readonly.v1",
)
sql_database = SQL_DATABASE.client(export=__name__ + ".sql_database")

RETRIEVER = ResourceContract(
    RetrieverAPI,
    class_name="retriever",
    object_kind="index",
    lowering="demo.tfidf.search.v1",
)
retriever = RETRIEVER.client(export=__name__ + ".retriever")

POLICY = ResourceContract(
    RetrieverAPI,
    class_name="policy_index",
    object_kind="index",
    lowering="demo.tfidf.policy.v1",
)
policy_index = POLICY.client(export=__name__ + ".policy_index")

SEARCH = ResourceContract(
    SearchAPI,
    class_name="search_corpus",
    object_kind="corpus",
    lowering="demo.frozen.search.v1",
)
search = SEARCH.client(export=__name__ + ".search")

TRAVEL = ResourceContract(
    TravelAPI,
    class_name="travel_database",
    object_kind="database",
    lowering="demo.travel.sqlite.v1",
)
travel = TRAVEL.client(export=__name__ + ".travel")

PYTHON_SESSION = ResourceContract(
    PythonSessionAPI,
    class_name="python_session",
    object_kind="process",
    lowering="demo.python.landlock.session.v1",
)
python_session = PYTHON_SESSION.client(export=__name__ + ".python_session")
