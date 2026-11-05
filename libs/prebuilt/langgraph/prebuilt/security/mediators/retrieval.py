"""Reusable bounded text-retrieval mediators for trusted library indexes."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from typing import Any

from langgraph.prebuilt.security.enforcement import HostAttestation, SupportLevel
from langgraph.prebuilt.security.mediators.contracts import ResourceContract
from langgraph.prebuilt.security.object_policy import ObjectGrantLine
from langgraph.prebuilt.security.resource_mediator import (
    ResourceInvocation,
    ResourceSupport,
)

_MAX_QUERY_BYTES = 4096
_MAX_RESULT_BYTES = 64 * 1024


class TextRetrievalAPI(ABC):
    """Query one setup-bound index and return inert text."""

    __slots__ = ()

    @abstractmethod
    def search(self, query: str) -> str:
        """Return bounded text selected from the registered index."""
        raise NotImplementedError


TEXT_RETRIEVAL = ResourceContract(
    TextRetrievalAPI,
    class_name="text_index",
    object_kind="index",
    lowering="library.text_retrieval.v1",
)
text_retrieval = TEXT_RETRIEVAL.client(export=__name__ + ".text_retrieval")

JSON_SEARCH = ResourceContract(
    TextRetrievalAPI,
    class_name="json_search_index",
    object_kind="index",
    lowering="library.json_search.v1",
)
json_search = JSON_SEARCH.client(export=__name__ + ".json_search")


class _RetrievalMediator:
    def assess(self, line: ObjectGrantLine, host: HostAttestation) -> ResourceSupport:
        return ResourceSupport(
            SupportLevel.EXACT,
            "query-only access to one setup-bound index with inert bounded output",
            witness="tests/security/test_library_mediators.py",
        )

    def validate(
        self,
        operation: str,
        arguments: Mapping[str, Any],
        context: ResourceInvocation,
    ) -> None:
        query = arguments.get("query")
        if type(query) is not str or len(query.encode("utf-8")) > _MAX_QUERY_BYTES:
            raise ValueError("retrieval query exceeds 4096 UTF-8 bytes")


def _bounded_text(value: str) -> str:
    if type(value) is not str or len(value.encode("utf-8")) > _MAX_RESULT_BYTES:
        raise ValueError("retrieval result exceeds 65536 UTF-8 bytes")
    return value


def sklearn_text_retrieval_resource(
    documents: Sequence[str], *, top_k: int = 5
) -> ResourceContract[TextRetrievalAPI]:
    """Build a setup-owned scikit-learn TF-IDF index.

    Import, fitting, and index construction happen during trusted setup. Tools
    receive only the generated `text_retrieval` interface.
    """
    if type(top_k) is not int or top_k < 1 or top_k > 20:
        raise ValueError("top_k must be between 1 and 20")
    snapshot = tuple(documents)
    if not snapshot or any(
        type(item) is not str or len(item.encode("utf-8")) > _MAX_RESULT_BYTES
        for item in snapshot
    ):
        raise ValueError("documents must be nonempty bounded strings")
    from sklearn.feature_extraction.text import TfidfVectorizer

    vectorizer = TfidfVectorizer(stop_words="english").fit(snapshot)
    matrix = vectorizer.transform(snapshot)

    class SklearnRetrieval(TextRetrievalAPI):
        def search(self, query: str) -> str:
            scores = (matrix @ vectorizer.transform([query]).T).toarray().ravel()
            indices = scores.argsort()[-top_k:][::-1]
            return _bounded_text("\n\n".join(snapshot[index] for index in indices))

    return TEXT_RETRIEVAL.bind(
        implementation=SklearnRetrieval(), mediator=_RetrievalMediator()
    )


def sklearn_json_search_resource(
    documents: Sequence[Mapping[str, str]], *, top_k: int = 3
) -> ResourceContract[TextRetrievalAPI]:
    """Build a setup-owned TF-IDF search index returning bounded JSON text."""
    if type(top_k) is not int or top_k < 1 or top_k > 20:
        raise ValueError("top_k must be between 1 and 20")
    snapshot = []
    texts = []
    for document in documents:
        if type(document) is not dict or any(
            type(key) is not str or type(value) is not str
            for key, value in document.items()
        ):
            raise ValueError("search documents must be plain string dictionaries")
        if set(document) not in ({"url", "content"}, {"url", "title", "content"}):
            raise ValueError(
                "search documents require url and content; title is optional"
            )
        copied = {
            "url": document["url"],
            "title": document.get("title", ""),
            "content": document["content"],
        }
        if any(
            len(value.encode("utf-8")) > _MAX_RESULT_BYTES for value in copied.values()
        ):
            raise ValueError("search document field exceeds 65536 UTF-8 bytes")
        snapshot.append(copied)
        texts.append(f"{copied['title']} {copied['content']}")
    if not snapshot:
        raise ValueError("search documents must be nonempty")
    from sklearn.feature_extraction.text import TfidfVectorizer

    vectorizer = TfidfVectorizer(stop_words="english").fit(texts)
    matrix = vectorizer.transform(texts)

    class SklearnJsonSearch(TextRetrievalAPI):
        def search(self, query: str) -> str:
            scores = (matrix @ vectorizer.transform([query]).T).toarray().ravel()
            indices = scores.argsort()[-top_k:][::-1]
            result = [
                {"url": snapshot[index]["url"], "content": snapshot[index]["content"]}
                for index in indices
            ]
            return _bounded_text(json.dumps(result, separators=(",", ":")))

    return JSON_SEARCH.bind(
        implementation=SklearnJsonSearch(), mediator=_RetrievalMediator()
    )


def static_text_retrieval_resource(result: str) -> ResourceContract[TextRetrievalAPI]:
    """Return one setup-bound inert response for every validated query."""
    result = _bounded_text(result)

    class StaticRetrieval(TextRetrievalAPI):
        def search(self, query: str) -> str:
            del query
            return result

    return TEXT_RETRIEVAL.bind(
        implementation=StaticRetrieval(), mediator=_RetrievalMediator()
    )


def static_json_search_resource(
    result: str = "[]",
) -> ResourceContract[TextRetrievalAPI]:
    """Return one setup-bound inert JSON response for every validated query."""
    result = _bounded_text(result)
    try:
        parsed = json.loads(result)
    except json.JSONDecodeError:
        raise ValueError("static search result must be JSON") from None
    if type(parsed) is not list:
        raise ValueError("static search result must be a JSON array")

    class StaticSearch(TextRetrievalAPI):
        def search(self, query: str) -> str:
            del query
            return result

    return JSON_SEARCH.bind(
        implementation=StaticSearch(), mediator=_RetrievalMediator()
    )


def langchain_text_retrieval_resource(
    retriever: Any, *, max_documents: int = 5
) -> ResourceContract[TextRetrievalAPI]:
    """Wrap a trusted LangChain retriever configured during application setup.

    Credentials, folder identifiers, and the retriever instance remain in the
    coordinator. Returned `Document` objects are reduced to bounded text.
    """
    if type(max_documents) is not int or not 1 <= max_documents <= 20:
        raise ValueError("max_documents must be between 1 and 20")
    invoke = getattr(retriever, "invoke", None)
    if not callable(invoke):
        raise TypeError("retriever must provide a trusted synchronous invoke method")

    class LangChainRetrieval(TextRetrievalAPI):
        def search(self, query: str) -> str:
            documents = invoke(query)
            if type(documents) not in {list, tuple}:
                raise TypeError("retriever must return a list or tuple of documents")
            texts = []
            for document in documents[:max_documents]:
                text = getattr(document, "page_content", None)
                if type(text) is not str:
                    raise TypeError("retriever documents require text page_content")
                texts.append(text)
            return _bounded_text("\n\n".join(texts))

    return TEXT_RETRIEVAL.bind(
        implementation=LangChainRetrieval(), mediator=_RetrievalMediator()
    )
