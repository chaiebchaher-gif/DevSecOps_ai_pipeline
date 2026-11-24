from fastapi import FastAPI

app = FastAPI(title="DevSecOps Target Service")

@app.get("/health")
def health_check():
    return {"status": "healthy"}
