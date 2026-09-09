from content_security.document.instruction import InstructionDetector


class RAGPoisonDetector(InstructionDetector):
    """Deterministic RAG instruction detector with no decision authority."""

