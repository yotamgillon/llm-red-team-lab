from target.rag import Retriever, load_docs


def test_kb_has_eight_docs_with_both_visibilities() -> None:
    docs = load_docs()
    assert len(docs) == 8
    assert {d.visibility for d in docs} == {"public", "internal"}


def test_refund_query_retrieves_poisoned_doc() -> None:
    hits = Retriever(load_docs()).search("What is your refund policy?")
    assert "kb_007" in [d.id for d in hits]
    poisoned = next(d for d in hits if d.id == "kb_007")
    assert "AI-ASSISTANT-INSTRUCTION" in poisoned.body


def test_unrelated_query_retrieves_nothing_and_results_differ() -> None:
    r = Retriever(load_docs())
    assert r.search("zzzz qqqq") == []
    assert r.search("lost stolen card")[0].id == "kb_004"
    assert r.search("overdraft fees")[0].id == "kb_002"


def test_internal_doc_retrievable_by_public_user_in_vulnerable_build() -> None:
    hits = Retriever(load_docs()).search("fraud desk escalation contacts")
    assert any(d.visibility == "internal" for d in hits)
