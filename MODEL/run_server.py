# run_server.py
"""
Root entrypoint to launch the AI Cyber Fraud & Phishing Detection Engine API.
"""
import uvicorn

if __name__ == "__main__":
    print("========================================================================")
    print("  Starting AI Cyber Fraud & Phishing Detection Engine API (FastAPI)     ")
    print("  Endpoints: /api/scan/domain | /api/scan/sms | /api/scan/payment        ")
    print("  Docs: http://localhost:8000/docs                                      ")
    print("========================================================================")
    uvicorn.run("api.server:app", host="0.0.0.0", port=8000, reload=True)
