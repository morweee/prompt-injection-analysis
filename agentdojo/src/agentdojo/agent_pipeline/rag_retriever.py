"""RAG (Retrieval-Augmented Generation) pipeline element using FAISS.

Demonstrates the RAG prompt-injection vulnerability: malicious documents
placed in the retrieval corpus get injected into the LLM's context.

Place this element BEFORE InitQuery in the pipeline so that the augmented
query string (with retrieved context appended) is what InitQuery turns into
a ChatUserMessage.

Dependencies (not in default install):
    pip install faiss-cpu sentence-transformers
"""

from collections.abc import Sequence

import numpy as np

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage


class RAGRetriever(BasePipelineElement):
    """Retrieves top-k documents from a FAISS index and appends them to the
    query before the LLM sees it.

    Args:
        docs: corpus of documents (mix of benign and, potentially, poisoned).
        top_k: number of documents to retrieve per query.
        model_name: sentence-transformers model for encoding.
        verbose: if True, print retrieved documents with malicious-doc warnings.
    """

    def __init__(
        self,
        docs: list[str],
        top_k: int = 2,
        model_name: str = "all-MiniLM-L6-v2",
        verbose: bool = True,
    ) -> None:
        import faiss
        from sentence_transformers import SentenceTransformer

        self.docs = docs
        self.top_k = top_k
        self.verbose = verbose
        self._encoder = SentenceTransformer(model_name)

        embeddings = self._encoder.encode(docs, convert_to_numpy=True, normalize_embeddings=True)
        self._index = faiss.IndexFlatIP(embeddings.shape[1])
        self._index.add(embeddings.astype(np.float32))

    def retrieve(self, query: str) -> list[tuple[float, str]]:
        """Return (score, doc) pairs for the top-k most similar documents."""
        q_emb = self._encoder.encode([query], convert_to_numpy=True, normalize_embeddings=True)
        scores, indices = self._index.search(q_emb.astype(np.float32), self.top_k)
        return [(float(scores[0][i]), self.docs[indices[0][i]]) for i in range(self.top_k)]

    @staticmethod
    def _is_malicious(doc: str) -> bool:
        upper = doc.upper()
        return any(kw in upper for kw in ("IGNORE PREVIOUS", "IGNORE ALL", "NEW TASK:", "SYSTEM OVERRIDE"))

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        results = self.retrieve(query)

        if self.verbose:
            print(f"\n{'─' * 64}")
            print(f"[RAG] Query : {query!r}")
            for i, (score, doc) in enumerate(results):
                tag = "  *** MALICIOUS ***" if self._is_malicious(doc) else ""
                preview = doc[:90].replace("\n", " ")
                print(f"  Doc {i + 1} (score={score:.3f}){tag}")
                print(f"        {preview}...")

        context = "\n\n".join(f"[Document {i + 1}]\n{doc}" for i, (_, doc) in enumerate(results))
        augmented_query = f"{query}\n\n<retrieved_context>\n{context}\n</retrieved_context>"

        extra_args = {**extra_args, "rag_retrieved": results}
        return augmented_query, runtime, env, messages, extra_args
