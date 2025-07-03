import chromadb
from sentence_transformers import SentenceTransformer
import google.generativeai as genai

def build_vector_db(documents, collection_name="docs"):
    client = chromadb.Client()
    collection = client.create_collection(collection_name)
    embedder = SentenceTransformer("all-MiniLM-L6-v2")
    embeddings = embedder.encode(documents).tolist()
    for i, doc in enumerate(documents):
        collection.add(
            documents=[doc],
            embeddings=[embeddings[i]],
            ids=[f"doc_{i}"]
        )
    return collection, embedder

def rag_query(query, collection, embedder, gemini_api_key, top_k=3):
    query_emb = embedder.encode([query]).tolist()[0]
    results = collection.query(
        query_embeddings=[query_emb],
        n_results=top_k
    )
    retrieved_docs = results['documents'][0]
    prompt = "다음 참고 문서를 바탕으로 질문에 답해주세요.\n"
    for doc in retrieved_docs:
        prompt += f"- {doc}\n"
    prompt += f"\n질문: {query}\n답변:"
    genai.configure(api_key=gemini_api_key)
    model = genai.GenerativeModel("gemini-2.5-flash")
    response = model.generate_content(prompt)
    return response.text
